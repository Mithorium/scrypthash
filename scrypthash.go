package scrypthash

// Package scrypthash inspired by crypto/bcrypt
import (
  "crypto/rand"
  "crypto/subtle"
  "errors"
  "fmt"
  "golang.org/x/crypto/scrypt"
  "io"
  "strconv"
  "github.com/tilinna/z85"
)

const (
  DefaultCost int = 14
  MinCost     int = 5
  MaxCost     int = 22
)

// The error returned from CompareHashAndPassword when a password and hash do not match.
var ErrMismatchedHashAndPassword = errors.New("mithorium/scrypthash: hashedPassword is not the hash of the given password")

// The error returned from CompareHashAndPassword when a hash is not a valid scrypthash hash.
var ErrHashInvalid = errors.New("mithorium/scrypthash: hashedPassword is not a scrypthashed password")

// The error returned from CompareHashAndPassword when a hash was created with a scrypthash algorithm newer than this implementation.
type HashVersionTooNewError byte

func (hv HashVersionTooNewError) Error() string {
  return fmt.Sprintf("mithorium/scrypthash: scrypthash algorithm version '%c' requested is newer than current version '%c'", byte(hv), version)
}

type InvalidCostError int

func (ic InvalidCostError) Error() string {
  return fmt.Sprintf("mithorium/scrypthash: cost %d is outside allowed range (%d,%d)", int(ic), int(MinCost), int(MaxCost))
}

const (
  prefix       = 's'
  version      = '1'
  costMemory   = 8
  costParallel = 1
  saltBytes    = 16
  hashBytes    = 32
  encodedSaltBytes = 20
  encodedHashBytes = 40
  hashStringBytes  = 64
)

type hashed struct {
  version  byte
  cost     int
  salt     []byte
  hash     []byte
}

func (p *hashed) Hash() []byte {
  arr := make([]byte, hashStringBytes)
  arr[0] = prefix
  arr[1] = p.version
  n := 2
  copy(arr[n:], []byte(fmt.Sprintf("%02x", p.cost)))
  n += 2
  copy(arr[n:], p.salt)
  n += encodedSaltBytes
  copy(arr[n:], p.hash)
  n += encodedHashBytes
  return arr[:n]
}

// GenerateFromPassword returns the scrypt hash of the password at the given cost.
func GenerateFromPassword(password []byte, cost int) ([]byte, error) {
  p, err := newFromPassword(password, cost)
  if err != nil {
    return nil, err
  }
  return p.Hash(), nil
}

// CompareHashAndPassword compares a scrypt hashed password with its possible
// plaintext equivalent. Returns nil on success, or an error on failure.
func CompareHashAndPassword(hashedPassword, password []byte) error {
  p, err := newFromHash(hashedPassword)
  if err != nil {
    return err
  }

  decodedSalt, err := z85Decode(p.salt, saltBytes)
  if err != nil {
    return ErrHashInvalid
  }

  otherHash, err := scrypt.Key(password, decodedSalt, 1<<uint(p.cost), costMemory, costParallel, hashBytes)
  if err != nil {
    return err
  }

  eh, err := z85Encode(otherHash, encodedHashBytes)
  if err != nil {
    return err
  }

  otherP := &hashed{p.version, p.cost, p.salt, eh}
  if subtle.ConstantTimeCompare(p.Hash(), otherP.Hash()) == 1 {
    return nil
  }

  return ErrMismatchedHashAndPassword
}

// Cost returns the hashing cost used to create the given hashed
// password. When, in the future, the hashing cost of a password system needs
// to be increased in order to adjust for greater computational power, this
// function allows one to establish which passwords need to be updated.
func Cost(hashedPassword []byte) (int, error) {
  p, err := newFromHash(hashedPassword)
  if err != nil {
    return 0, err
  }
  return p.cost, nil
}

func newFromPassword(password []byte, cost int) (*hashed, error) {
  p := new(hashed)
  p.version = version

  err := checkCost(cost)
  if err != nil {
    return nil, err
  }
  p.cost = cost

  unencodedSalt := make([]byte, saltBytes)
  _, err = io.ReadFull(rand.Reader, unencodedSalt)
  if err != nil {
    return nil, err
  }

  es, err := z85Encode(unencodedSalt, encodedSaltBytes)
  if err != nil {
    return nil, err
  }
  p.salt = es

  hash, err := scrypt.Key(password, unencodedSalt, 1<<uint(cost), costMemory, costParallel, hashBytes)
  if err != nil {
    return nil, err
  }

  eh, err := z85Encode(hash, encodedHashBytes)
  if err != nil {
    return nil, err
  }
  p.hash = eh

  return p, nil
}

func newFromHash(hashedSecret []byte) (*hashed, error) {
  if len(hashedSecret) != hashStringBytes {
    fmt.Println(len(hashedSecret))
    return nil, ErrHashInvalid
  }
  p := new(hashed)
  n, err := p.decodeVersion(hashedSecret)
  if err != nil {
    return nil, err
  }
  hashedSecret = hashedSecret[n:]
  n, err = p.decodeCost(hashedSecret)
  if err != nil {
    return nil, err
  }
  hashedSecret = hashedSecret[n:]

  p.salt = make([]byte, encodedSaltBytes)
  copy(p.salt, hashedSecret[:encodedSaltBytes])

  hashedSecret = hashedSecret[encodedSaltBytes:]
  p.hash = make([]byte, encodedHashBytes)
  copy(p.hash, hashedSecret)

  return p, nil
}


func (p *hashed) decodeVersion(sbytes []byte) (int, error) {
  if sbytes[0] != prefix {
    return -1, ErrHashInvalid
  }
  if sbytes[1] > version {
    return -1, HashVersionTooNewError(sbytes[1])
  }
  p.version = sbytes[1]

  return 2, nil
}

// sbytes should begin where decodeVersion left off.
func (p *hashed) decodeCost(sbytes []byte) (int, error) {
  cost, err := strconv.ParseInt(string(sbytes[0:2]),16,32)
  if err != nil {
    return -1, err
  }
  err = checkCost(int(cost))
  if err != nil {
    return -1, err
  }
  p.cost = int(cost)
  return 2, nil
}

func (p *hashed) String() string {
  return string(p.Hash())
}

func z85Encode(binary []byte, encodedSize int) ([]byte, error) {
  encoded := make([]byte, encodedSize)
  n, err := z85.Encode(encoded, binary)
  if err != nil {
    return nil, err
  }
  return encoded[:n], nil
}

func z85Decode(encoded []byte, decodedSize int) ([]byte, error) {
  decoded := make([]byte, decodedSize)
  n, err := z85.Decode(decoded, encoded)
  if err != nil {
    return nil, err
  }
  return decoded[:n], nil
}

func checkCost(cost int) error {
  if cost < MinCost || cost > MaxCost {
    return InvalidCostError(cost)
  }
  return nil
}
