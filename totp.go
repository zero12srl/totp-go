package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
  "strings"
  time "time"
	"fmt"
  "errors"
  "hash"
	"strconv"
	"log"
	big "math/big"
)

/*
 * This is an implementation of the OATH TOTP algorithm based on RFC 6238 and RFC 4226
 * Visit www.openauthentication.org for more information.
 *
 * @author Pietro Tollot, Zero12 s.r.l
 */

 /*
  * This function uses the crypto package to provide the crypto algorithm.
  * HMAC computes a Hashed Message Authentication Code with the
  * crypto hash algorithm as a parameter.
  *
  * @param crypto: the crypto algorithm [HmacSHA1 | HmacSHA256 | HmacSHA512]
  * @param keyBytes: the bytes to use for the HMAC key
  * @param text: the message or text to be authenticated
  */

func hmac_sha(crypto string, keyBytes []byte, text []byte) ([]byte, error) {

  var mac hash.Hash
  var hashed_text []byte

  switch crypto {
    default: return nil, errors.New("crypto: algorithm not found")
    case "HmacSHA1": mac = hmac.New(sha1.New, keyBytes)
    case "HmacSHA256": mac = hmac.New(sha256.New, keyBytes)
    case "HmacSHA512": mac = hmac.New(sha512.New, keyBytes)
  }

  mac.Write(text)
  hashed_text = mac.Sum(nil)

  return hashed_text, nil
}

func hexStr2Bytes(hex string) []byte{
		// Adding one byte to get the right conversion
		// Values starting with "0" can be converted
		var bArray []byte
		temp := big.NewInt(0)
		temp, _ = temp.SetString("10" + hex, 16)
		bArray = temp.Bytes()

		// Copy all the REAL bytes, not the "first"
		ret := bArray[1:]
		return ret;
}

 var DIGITS_POWER = [9]int{1,10,100,1000,10000,100000,1000000,10000000,100000000}

/*
 * These funtions generates a TOTP value for the given set of parameters.
 *
 * @param key: the shared secret, HEX encoded
 * @param time: a value that reflects a time
 * @param returnDigits: number of digits to return
 *
 * @return: a numeric String in base 10 that includes
 *              {@link truncationDigits} digits
 */

func generateTOTP1(key, time, returnDigits string) (string, error){
		hashCode, err := generateTOTP(key, time, returnDigits, "HmacSHA1")
		if err != nil {
				return "", err
		}
    return hashCode, nil
}

func generateTOTP256(key, time, returnDigits string) (string, error){
	hashCode, err := generateTOTP(key, time, returnDigits, "HmacSHA256")
	if err != nil {
			return "", err
	}
	return hashCode, nil
}

func generateTOTP512(key, time, returnDigits string) (string, error){
	hashCode, err := generateTOTP(key, time, returnDigits, "HmacSHA512")
	if err != nil {
			return "", err
	}
	return hashCode, nil
}

/*
 * This function generates a TOTP value for the given
 * set of parameters.
 *
 * @param key: the shared secret, HEX encoded
 * @param time: a value that reflects a time
 * @param returnDigits: number of digits to return
 * @param crypto: the crypto function to use
 *
 * @return: a numeric String in base 10 that includes
 *              {@link truncationDigits} digits
 */

 func generateTOTP(key, time, returnDigits, crypto string) (string, error){

  codeDigits, err := strconv.Atoi(returnDigits)
	if err != nil {
		return "", err
	}

  keyBytes := hexStr2Bytes(key)  // Get the HEX in a Byte[]
  if err != nil {
    return "", err
  }

  for len(time) < 16 {
      time = "0" + time
		}

  msg := hexStr2Bytes(time)  // Get the HEX in a Byte[]
  if err != nil {
    return "", err
  }

	var hash []byte

  hash, err = hmac_sha(crypto, keyBytes, msg)
	if err != nil {
    return "", err
  }

	// truncate the hashed value
  off := hash[len(hash) - 1] & 0xf;
	offset := int64(off)

	var binar [4]byte

	binar[0] = (hash[offset] & 0x7f)
	binar[1] = (hash[offset + 1])
	binar[2] = (hash[offset + 2])
	binar[3] = (hash[offset + 3])

	binarSlice := binar[:]

	// see array byte as integer
	temp := big.NewInt(0)
	binary := temp.SetBytes(binarSlice)


  otp := binary.Uint64() % uint64(DIGITS_POWER[codeDigits])

	result := strconv.FormatInt(int64(otp), 10)

	// limit digits
  for len(result) < codeDigits {
      result = "0" + result;
  }

  return result, nil
}

//===============
//=== singleton
//===============
// a singleton implementation of a totp verifier that uses
// the procedures defined above

var TotpReference *TotpServer

func init(){
	initObj, err := totpFactory("HmacSHA1", 30, 0)
	TotpReference = initObj
	if err != nil {
		log.Fatal(err)
	}
}

type TotpServer struct {
	seeds 		map[string] string
	method 		string
	interval 	int64
	T0 				int64
}

// factory of a TotpServer with:
// @method:    [HmacSHA1 | HmacSHA256 | HmacSHA512]
// @interval:  interval after wich totp change
// @T0:				 time offset from Unix time

func totpFactory(method string, interval, T0 int64) (*TotpServer, error){

	if method != "HmacSHA1" && method != "Hmac256" && method != "Hmac512" {
		return nil, fmt.Errorf("unkonwn method")
	}

	var totpObj *TotpServer = &TotpServer{}
	totpObj.method = method
	totpObj.interval = interval
	totpObj.T0 = T0

	totpObj.seeds = map[string]string{}

	return totpObj, nil
}

// associate user with seed
func (this *TotpServer) Register(username string, seed string) {
	this.seeds[username] = seed
}

func (this *TotpServer) Delete(username string) {
	delete(this.seeds, username)
}

// get list of users registered
func (this *TotpServer) GetUsernames() []string {
		var keys []string
    for k := range this.seeds {
        keys = append(keys, k)
    }
		return keys
}

// verify if a user is in the struct
func (this *TotpServer) UserVerify(username string) bool{
	_, present := this.seeds[username]
	return present
}

// verify if the passcode is correct for the user passed
func (this *TotpServer) Verify(username, passcode string) (bool, error){
	now := time.Now()
	seconds := now.Unix()
	var counter int64 = ((seconds - this.T0)/this.interval)

	steps := strconv.FormatInt(counter, 16)
	steps = strings.ToUpper(steps)
	for len(steps) < 16 {
		 steps = "0" + steps
	 }

	code, err:= generateTOTP(this.seeds[username], steps, "8", this.method)
	if err != nil {
		 return false, err
	 }

	 if code == passcode {
		 return true, nil
	 }else{
		 return false, nil
	 }

}
