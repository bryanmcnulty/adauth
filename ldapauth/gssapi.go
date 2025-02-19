package ldapauth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/RedTeamPentesting/adauth/pkinit"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/types"

	krb5GSSAPI "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/spnego"

	krb5Crypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

type gssapiClient struct {
	*client.Client
	ccache *credentials.CCache

	ekey   types.EncryptionKey
	Subkey types.EncryptionKey

	BindCertificate *x509.Certificate
}

func newClientFromCCache(
	username string, domain string, ccachePath string, krb5Conf *config.Config,
) (*gssapiClient, error) {
	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, err
	}

	c, err := client.NewFromCCache(ccache, krb5Conf, client.DisablePAFXFAST(true))
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "tgt not found") {
		// client.NewFromCCache only accepts ccaches that contain at least one
		// TGT, however, we want to support ccaches that only contain a service
		// ticket. Therefore, we use a dummy client, and pull the service ticket
		// from the ccache ourselves instead of asking the client.
		return &gssapiClient{
			Client: client.NewWithPassword(username, domain, "", krb5Conf, client.DisablePAFXFAST(true)),
			ccache: ccache,
		}, nil
	}

	if err != nil {
		return nil, err
	}

	return &gssapiClient{Client: c}, nil
}

func newPKINITClient(
	ctx context.Context, username string, domain string, cert *x509.Certificate, key *rsa.PrivateKey,
	krb5Conf *config.Config, opts ...pkinit.Option,
) (*gssapiClient, error) {
	ccache, err := pkinit.Authenticate(ctx, username, domain, cert, key, krb5Conf, opts...)
	if err != nil {
		return nil, fmt.Errorf("pkinit: %w", err)
	}

	c, err := client.NewFromCCache(ccache, krb5Conf, client.DisablePAFXFAST(true))
	if err != nil {
		return nil, fmt.Errorf("initialize Kerberos client from PKINIT ccache: %w", err)
	}

	return &gssapiClient{Client: c}, nil
}

// Close deletes any established secure context and closes the client.
func (client *gssapiClient) Close() error {
	client.Client.Destroy()

	return nil
}

// DeleteSecContext destroys any established secure context.
func (client *gssapiClient) DeleteSecContext() error {
	client.ekey = types.EncryptionKey{}
	client.Subkey = types.EncryptionKey{}

	return nil
}

func (client *gssapiClient) getServiceTicket(target string) (tkt messages.Ticket, key types.EncryptionKey, err error) {
	// ask our own copy of the ccache for a suitable service ticket before asking the client
	if client.ccache != nil {
		entry, ok := client.ccache.GetEntry(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, target))
		if !ok {
			return tkt, key, fmt.Errorf("CCACHE does not contain service ticket for %q", target)
		}

		if entry.Key.KeyType == etypeID.RC4_HMAC {
			return tkt, key, fmt.Errorf("RC4 tickets from ccache are currently not supported " +
				"(see https://github.com/jcmturner/gokrb5/pull/498), but you should be able " +
				"to request an AES256 ticket instead (even with NT hash)")
		}

		return tkt, entry.Key, tkt.Unmarshal(entry.Ticket)
	}

	return client.Client.GetServiceTicket(target)
}

func (client *gssapiClient) newKRB5TokenAPREQ(
	tkt messages.Ticket, ekey types.EncryptionKey,
) (*spnego.KRB5Token, error) {
	gssapiFlags := []int{krb5GSSAPI.ContextFlagInteg, krb5GSSAPI.ContextFlagConf, krb5GSSAPI.ContextFlagMutual}

	// this actually does nothing important, we simply use it to obtain a dummy
	// KRB5Token with tokID set, which unfortunately is private, so we cannot
	// initialize it ourselves.
	token, err := spnego.NewKRB5TokenAPREQ(client.Client, tkt, ekey, gssapiFlags, []int{flags.APOptionMutualRequired})
	if err != nil {
		return nil, err
	}

	// build a custom authenticator that supports channel binding
	authenticator, err := krb5TokenAuthenticator(
		client.Credentials.Realm(), client.Credentials.CName(), client.BindCertificate, gssapiFlags)
	if err != nil {
		return nil, fmt.Errorf("create authenticator: %w", err)
	}

	APReq, err := messages.NewAPReq(
		tkt,
		ekey,
		authenticator,
	)
	if err != nil {
		return nil, err
	}

	types.SetFlag(&APReq.APOptions, flags.APOptionMutualRequired)

	// put the APReq with custom authenticator into the dummy RKB5Token
	token.APReq = APReq

	return &token, nil
}

// InitSecContext initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *gssapiClient) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	switch input {
	case nil:
		tkt, ekey, err := client.getServiceTicket(target)
		if err != nil {
			return nil, false, err
		}

		client.ekey = ekey

		token, err := client.newKRB5TokenAPREQ(tkt, ekey)
		if err != nil {
			return nil, false, err
		}

		output, err := token.Marshal()
		if err != nil {
			return nil, false, err
		}

		return output, true, nil

	default:
		var token spnego.KRB5Token

		err := token.Unmarshal(input)
		if err != nil {
			return nil, false, err
		}

		var completed bool

		if token.IsAPRep() {
			completed = true

			encpart, err := krb5Crypto.DecryptEncPart(token.APRep.EncPart, client.ekey, keyusage.AP_REP_ENCPART)
			if err != nil {
				return nil, false, err
			}

			part := &messages.EncAPRepPart{}

			if err = part.Unmarshal(encpart); err != nil {
				return nil, false, err
			}

			client.Subkey = part.Subkey
		}

		if token.IsKRBError() {
			return nil, !false, token.KRBError
		}

		return make([]byte, 0), !completed, nil
	}
}

// Fixed version of SASL authentication based on https://github.com/go-ldap/ldap/pull/537.
func (client *gssapiClient) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	token := &krb5GSSAPI.WrapToken{}

	err := unmarshalWrapToken(token, input, true)
	if err != nil {
		return nil, err
	}

	if (token.Flags & 0b1) == 0 {
		return nil, fmt.Errorf("got a Wrapped token that's not from the server")
	}

	key := client.ekey
	if (token.Flags & 0b100) != 0 {
		key = client.Subkey
	}

	_, err = token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, err
	}

	pl := token.Payload
	if len(pl) != 4 {
		return nil, fmt.Errorf("server send bad final token for SASL GSSAPI Handshake")
	}

	// We never want a security layer
	payload := []byte{0, 0, 0, 0}

	encType, err := krb5Crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token = &krb5GSSAPI.WrapToken{
		Flags:     0b100,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	output, err := token.Marshal()
	if err != nil {
		return nil, err
	}

	return output, nil
}

func unmarshalWrapToken(wt *krb5GSSAPI.WrapToken, data []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header
	if len(data) < 16 {
		return errors.New("bytes shorter than header length")
	}

	// Is the Token ID correct?
	expectedWrapTokenId := []byte{0x05, 0x04}
	if !bytes.Equal(expectedWrapTokenId, data[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s",
			hex.EncodeToString(expectedWrapTokenId), hex.EncodeToString(data[0:2]))
	}

	// Check the acceptor flag
	flags := data[2]
	isFromAcceptor := flags&0x01 == 1

	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}

	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}

	// Check the filler byte
	if data[3] != krb5GSSAPI.FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(data[3:4]))
	}

	checksumL := binary.BigEndian.Uint16(data[4:6])

	// Sanity check on the checksum length
	if int(checksumL) > len(data)-krb5GSSAPI.HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(data), checksumL)
	}

	payloadStart := 16 + checksumL

	wt.Flags = flags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(data[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(data[8:16])
	wt.CheckSum = data[16:payloadStart]
	wt.Payload = data[payloadStart:]

	return nil
}

func krb5TokenAuthenticator(
	realm string, cname types.PrincipalName, cert *x509.Certificate, flags []int,
) (types.Authenticator, error) {
	// RFC 4121 Section 4.1.1
	auth, err := types.NewAuthenticator(realm, cname)
	if err != nil {
		return auth, krberror.Errorf(err, krberror.KRBMsgError, "error generating new authenticator")
	}

	// https://datatracker.ietf.org/doc/html/rfc4121#section-4.1.1
	checksum := make([]byte, 24)

	if cert != nil {
		hash := ChannelBindingHash(cert)
		if len(hash) != 16 {
			return auth, fmt.Errorf("unexpected channel binding hash size: %d, expected 16", len(hash))
		}

		binary.LittleEndian.PutUint32(checksum[:4], uint32(len(hash)))
		copy(checksum[4:20], hash)
	}

	binary.LittleEndian.PutUint32(checksum[:4], 16)

	for _, flag := range flags {
		if flag == krb5GSSAPI.ContextFlagDeleg {
			checksum = append(checksum, make([]byte, 28-len(checksum))...) //nolint:makezero
		}

		f := binary.LittleEndian.Uint32(checksum[20:24])
		f |= uint32(flag)

		binary.LittleEndian.PutUint32(checksum[20:24], f)
	}

	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  checksum,
	}

	return auth, nil
}
