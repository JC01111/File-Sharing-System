package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings


import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	"encoding/hex"
	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {
	_ = strings.Compare("a", "b")
	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}


//////////////////////////////////****** Struct Defintions ******//////////////////////////////////
type User struct {
	//These can be generated evertime a user logs in
	username string
	rootKey []byte
	//Want to hold on to these between serializing and deserializing
	DecryptRSA 	userlib.PKEDecKey
	SigningKey	userlib.DSSignKey
	//CP can deterministically compute UUID's and find FileReferences
	//just keep track of which files aready created by stashing their names
	//FileNames is a pointer to a map[string]bool
	//true: user is owner
	//false: user is not the owner
}

//Confidentiality + Integrity
type SecureData struct {
	Ciphertext	[]byte
	Mac			[]byte
}
type FileReference struct {
	//can be retrieved from user input
	filename string
	//used for file sharing, the map stored corresponds to the shares the owner has done
	//used to gain access to middleman or File depending on ownership
	RootKey []byte
	//If user is not the owner they must access the file through the MiddlePtr
	//If owner MiddlePtr is nil
	//To access need to use rootkey of the USER NOT the FileReference!
	MiddleManPtr	uuid.UUID
	//not uuid.Nil if user is the file owner
	FilePtr		uuid.UUID
}

type MiddleManEntry struct {
	MiddleManPtr uuid.UUID
	//root key to access the middleman 
	RootKey	[]byte
}

type MiddleMan struct {
	//CP: The owner of the file generates these keys they are not unique to a user
	//so they cannot be deterministically generated
	//Keys for accessing file use rootkey to deterministically create symmetric keys
	RootKey []byte
	FilePtr 	uuid.UUID
}
type File struct {
	// JC added
	//CP: Cant traverse whole list to append need to be able to do it efficiently
	//Append by just accessing the tail
	HeadRootKey []byte
	TailRootKey []byte
	Head uuid.UUID
	Tail uuid.UUID
}

type FileNode struct {
	//NodeRootKey is used to derive the symmetric keys to gain access
	//to Next and the Content
	RootKey []byte
	Next uuid.UUID
	ContentPtr uuid.UUID
}
//Just a wrapper around a byte slice to save and retrieve content
type FileContent struct {
	Content []byte
}

type SharingMap struct {
	MiddleManMap map[string]MiddleManEntry
}

//Used by user when accepting an invitation
//should have encrypted symmetric keys
//digital signature by inviter to verify the keys
type Invitation struct {
	SignatureOfEncryptedRootKey 	[]byte		//used to ensure integrity on sent keys
	EncryptedRootKey				[]byte		//Keys encrypted with user PublicKey
	MiddleManPtr				uuid.UUID		//pointer to SecureData representing a middleman
}

//////////////////////////////////****** Defined Variable Start ******//////////////////////////////////
// NOTE: The following methods have toy (insecure!) implementations.

const PK_SUFFIX string = "PublicKey"
const VERIFY_SUFFIX string = "VerifySignature"
const DICTIONARY_SUFFIX = "User Dictionary"
const SHARE_SUFFIX = "Sharing Map"
var MAC_USER_PURPOSE []byte = []byte("user-mac-key")
var ENCRYPT_USER_PURPOSE []byte = []byte("user-encrypt-key")
const KEY_SIZE int = 16
const UUID_SIZE int = 16
const IV_SIZE int = 16
var FR_ENCRYPT_PURPOSE []byte = []byte("file-reference-encrypt-key")
var FR_MAC_PURPOSE []byte = []byte("file-reference-mac-key")
var FILE_NODE_ENCRYPT_PURPOSE = []byte("filenode-encrypt-key")
var FILE_NODE_MAC_PURPOSE = []byte("filenode-mac-key")
var FN_CONTENT_ENCRYPT_PURPOSE = []byte("filenode-content-encrypt-key")
var FN_CONTENT_MAC_PURPOSE = []byte("filenode-content-mac-key")
var MM_ENCRYPT_PURPOSE = []byte("middleman-encrypt_key")
var MM_MAC_PURPOSE = []byte("middleman-mac-key")
var ACCESS_FILE_ENCRYPT_PURPOSE = []byte("fileaccess-encrypt-key")
var ACCESS_FILE_MAC_PURPOSE = []byte("fileaccess-mac-key")
const SHARING_MAP_ENCRYPT_PURPOSE = "share-map-encrypt-purp"
var SHARING_MAP_MAC_PURPOSE	 = "share-map-mac-purp"

//////////////////////////////////****** Helper Functions start ******//////////////////////////////////


func generateSymmetricKeys(rootKey []byte, encryptPurpose []byte, macPurpose []byte) (encryptKey []byte, macKey []byte, err error) {
	var e error = nil
	//create encyption and HMAC keys
	encryptKey, e = userlib.HashKDF(rootKey, encryptPurpose)
	encryptKey = encryptKey[:KEY_SIZE]
	if (e != nil) {
		e = errors.New("ERROR: Failed to create symmetric keys.")
	}
	macKey, e = userlib.HashKDF(rootKey, macPurpose)
	macKey = macKey[:KEY_SIZE]
	if (e != nil) {
		e = errors.New("ERROR: Failed to create symmetric keys.")
	}
	return encryptKey, macKey, e
}
////////////////////////****** Symmetric Key Generation ******////////////////////////////////
func generateSharingMapKeys(userRootKey []byte, filename string) ([]byte, []byte, error){
	//use filename so not all MiddleManMaps of a user share the same encrypt and mac keys
	encryptKey, macKey, e := generateSymmetricKeys(
		userRootKey, 
		[]byte(SHARING_MAP_ENCRYPT_PURPOSE + filename), 
		[]byte(SHARING_MAP_MAC_PURPOSE + filename))
	if e != nil {
		return nil, nil, errors.New("Failed to generate MiddleManMap keys.")
	}
	return encryptKey, macKey, nil
}
func generateFileReferenceKeys(rootKey []byte) ([]byte, []byte, error){
	encryptKey, macKey, e := generateSymmetricKeys(rootKey, FR_ENCRYPT_PURPOSE, FR_MAC_PURPOSE)
	if e != nil {
		return nil, nil, errors.New("Failed to generate file reference keys.")
	}
	return encryptKey, macKey, nil
}
func generateFileNodeKeys(rootKey []byte) ([]byte, []byte, error){
	encryptKey, macKey, e := generateSymmetricKeys(rootKey, FILE_NODE_ENCRYPT_PURPOSE, FILE_NODE_MAC_PURPOSE)
	if e != nil {
		return nil, nil, errors.New("Failed to generate file node keys.")
	}
	return encryptKey, macKey, nil
}
func generateMiddleManKeys(rootKey []byte) ([]byte, []byte, error) {
	encryptKey, macKey, e := generateSymmetricKeys(rootKey, MM_ENCRYPT_PURPOSE, MM_MAC_PURPOSE)
	if e != nil {
		return nil, nil, errors.New("Failed to generate middleman keys.")
	}
	return encryptKey, macKey, nil
}
func generateFileAccessKeys(rootKey []byte) ([]byte, []byte, error) {
	encryptKey, macKey, e := generateSymmetricKeys(rootKey, ACCESS_FILE_ENCRYPT_PURPOSE, ACCESS_FILE_MAC_PURPOSE)
	if e != nil {
		return nil, nil, errors.New("Failed to generate middleman keys.")
	}
	return encryptKey, macKey, nil
}

func generateContentKeys(rootKey []byte) ([]byte, []byte, error) {
	encryptKey, macKey, e := generateSymmetricKeys(rootKey, FN_CONTENT_ENCRYPT_PURPOSE, FN_CONTENT_MAC_PURPOSE)
	if e != nil {
		return nil, nil, errors.New("Failed to generate content keys.")
	}
	return encryptKey, macKey, nil
}

func generateUserKeys(rootKey []byte) ([]byte, []byte, error) {
	encryptKey, macKey, e := generateSymmetricKeys(rootKey, ENCRYPT_USER_PURPOSE, MAC_USER_PURPOSE)
	if e != nil {
		return nil, nil, errors.New("Failed to generate user keys.")
	}
	return encryptKey, macKey, nil
}
////////////////////////****** Function Helpers ******////////////////////////////////

//Input: val a byte sequence used to produce a UUID
//Output: The uuid generated. Returns error to indicate function failed
//Side Effects: None
func deriveUUID(val []byte) (uuid.UUID, error) {
	userHash := userlib.Hash(val)[:UUID_SIZE]
	userUUID, err := uuid.FromBytes(userHash)
	if err != nil {
		return uuid.Nil, errors.New("ERROR: Failed to create a UUID")
	}
	return userUUID, nil
}

//Input: user is a Pointer to a user
//Output: Error if function fails
//Side effects: creates two RSA keypairs. One for RSA encryption the other for signing
//user struct stores its private keys at the end of the function
//user's public keys put on the keystore

func generatePublicKeys(user *User) (err error){
	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return errors.New("ERROR: Failed to create public key pair.")
	}
	user.DecryptRSA = privateKey
	userlib.KeystoreSet(fmt.Sprint(user.username, PK_SUFFIX), publicKey)
	//generate key pair for digital signatures
	signKey, verifyKey, err := userlib.DSKeyGen()
	if err != nil {
		return errors.New("ERROR: Failed to create public key pair.")
	}
	user.SigningKey = signKey
	userlib.KeystoreSet(fmt.Sprint(user.username, VERIFY_SUFFIX), verifyKey)
	return nil
}

//Input: the two symmetric keys to encrypt-then-MAC, a uuid to store serialized data at,
//a data object to serialize
//Returns: An error if function fails
//Side effects: obj is serialized and then Encrypt-then-MAC is performed on the serialize bytes
//Result stored in a SecureData struct which is then serialized and put in the Datastore
func serializeData(encryptKey []byte, macKey []byte, userUUID uuid.UUID, data interface{}) (err error) {
	serializedData, err := json.Marshal(data)
	if err != nil {
		return errors.New("ERROR: Failed to serialize data")
	}
	ciphertext := userlib.SymEnc(encryptKey, userlib.RandomBytes(IV_SIZE), serializedData)
	mac, err := userlib.HMACEval(macKey, ciphertext)
	if err != nil {
		return errors.New("ERROR: Failed to serialize data")
	}
	secureData := SecureData{ciphertext, mac}
	serialSecureData, err := json.Marshal(secureData)
	if err != nil {
		return errors.New("ERROR: Failed to serialize data")
	}
	userlib.DatastoreSet(userUUID, serialSecureData)
	return nil
}
//Input: serial data (Should represent a Secure Data object!), two symmetric keys for Encrypt-then-MAC, obj should be a pointer to an object
//Output: An error if the function fails
//Side effects: obj should now point to an object of it's type retrieved from Datastore
func deserializeData(serialData []byte, encryptKey []byte, macKey []byte, obj interface{}) (e error){
	var secureData SecureData
	err := json.Unmarshal(serialData, &secureData)
	if err != nil {
		return errors.New("ERROR: Failed to unmarshal secure data")
	}
	//compute the HMAC on ciphertext and check it matches
	var testMac []byte
	testMac, e = userlib.HMACEval(macKey, secureData.Ciphertext)
	if !userlib.HMACEqual(testMac, secureData.Mac) {
		return errors.New("ERROR: MACs do not match")
	}
	//else decrpyt the data
	serialUser := userlib.SymDec(encryptKey, secureData.Ciphertext)
	e = json.Unmarshal(serialUser, obj)
	if e != nil {
		return errors.New("ERROR: Failed to unmarshal serial data")
	}
	return nil
}

func getMiddleMan(rootKey []byte, location uuid.UUID) (MiddleMan, error) {
	var middleman = MiddleMan{}
	serialBytes, gotSerialBytes := userlib.DatastoreGet(location)
	if !gotSerialBytes {
		return MiddleMan{}, errors.New("Error from getMiddleMan() could not get serial bytes")
	}
	encryptKey, macKey, e := generateMiddleManKeys(rootKey)
	if e != nil {
		return MiddleMan{}, errors.New("Error from getMiddleMan() " + e.Error())
	}
	e = deserializeData(serialBytes, encryptKey, macKey, &middleman)
	if e != nil {
		return MiddleMan{}, errors.New("Error from getMiddleMan() " + e.Error())
	}
	return middleman, nil
}

func getSharingMap(userRootKey []byte, fr FileReference) (SharingMap, error){
	//get the keys
	encryptKey, macKey, err := generateSharingMapKeys(userRootKey, fr.filename)
	if err != nil {
		return SharingMap{}, errors.New("Error from getSharingMap() " + err.Error())
	}
	//get the location
	location, err := sharingMapUUID(userRootKey, fr)
	if err != nil {
		return SharingMap{}, errors.New("Error from getSharingMap() " + err.Error())
	}
	//get the SharingMap
	serialBytes, gotSerialBytes := userlib.DatastoreGet(location)
	if !gotSerialBytes {
		return SharingMap{}, errors.New("Error from getSharingMap() could not get serial bytes")
	}
	var sharingMap = SharingMap{}
	err = deserializeData(serialBytes, encryptKey, macKey, &sharingMap)
	if err != nil {
		return SharingMap{}, errors.New("Error from getSharingMap() " + err.Error())
	}
	return sharingMap, nil
}

func saveSharingMap(userRootKey []byte, fr FileReference, shareMap SharingMap) (error) {
	//get the location
	location, err := sharingMapUUID(userRootKey, fr)
	if err != nil {
		return errors.New("Error from saveSharingMap() " + err.Error())
	}
	encryptKey, macKey, err := generateSharingMapKeys(userRootKey, fr.filename)
	if err != nil {
		return errors.New("Error from getSharingMap() " + err.Error())
	}
	//store the sharing map
	err = serializeData(encryptKey, macKey, location, shareMap)
	if err != nil {
		return errors.New("Error from getSharingMap() " + err.Error())
	}
	return nil
}

func sharingMapUUID(userRootKey []byte, fr FileReference) (uuid.UUID, error) {
	byteSequence := []byte(hex.EncodeToString(userRootKey) + fr.filename + SHARE_SUFFIX)
	return deriveUUID(byteSequence)
}

//Input: a FileReference instance, isOwner boolean flag to indicate ownership
//Returns: File obj from datastore
//Side effects: None

//If isOwner is true then user.EncryptKey, user.MacKey correspond to the keys to access the File obj
//Else keys correspond to the MiddleMan on the Datastore
func getFile(fileRef FileReference, isOwner bool) (File, error) {
	var file *File = &File{}
	if !isOwner {
		// Recover the MiddleMan struct
		middleman, err := getMiddleMan(fileRef.RootKey, fileRef.MiddleManPtr)
		if err != nil {
			return File{}, errors.New("ERROR from getFile() " + err.Error())
		}
		// Recover the File struct
		fileBytes, serialFileBytesExist := userlib.DatastoreGet(middleman.FilePtr)
		if !serialFileBytesExist {
			return File{}, errors.New("ERROR: File UUID does not point to anything.")
		}
		encryptKey, macKey, err := generateFileAccessKeys(middleman.RootKey)
		err = deserializeData(fileBytes, encryptKey, macKey, file)
		if err != nil {
			return File{}, errors.New("ERROR from getFile() " + err.Error())
		}
	} else {	// If isOwner just use FilePtr to get the file
		fileBytes, serialFileBytesExist := userlib.DatastoreGet(fileRef.FilePtr)
		if !serialFileBytesExist {
			return File{}, errors.New("ERROR: File UUID does not point to anything.")
		}
		encryptKey, macKey, err := generateFileAccessKeys(fileRef.RootKey)
		if err != nil {
			return File{}, errors.New("ERROR from getFile() " + err.Error())
		}
		err = deserializeData(fileBytes, encryptKey, macKey, file)
		if err != nil {
			return File{}, errors.New("ERROR from getFile() " + err.Error())
		}
	}
	return *file, nil
}
//creates a new node and stores the content on the datastore
//Input: content to store in node
//Output: pointer to new file node
//Side effects: content of new node stored on datastore
func createNewNode(content []byte) (FileNode, error) {
	//create a new node with the content
	var newNode FileNode = FileNode{
		RootKey: userlib.RandomBytes(KEY_SIZE),
		Next: uuid.Nil,
		ContentPtr: uuid.New()}
	//save the content on the datastore
	//generate the symmetric keys
	encryptKey, macKey, err := generateContentKeys(newNode.RootKey)
	if err != nil {
		return FileNode{}, errors.New(fmt.Sprint("failed to create new node ", err.Error()))
	}
	//save the content using the keys
	var fileContent FileContent = FileContent{content}
	err = serializeData(encryptKey, macKey, newNode.ContentPtr, fileContent)
	if err != nil {
		return FileNode{}, errors.New(fmt.Sprint("failed to create new node ", err.Error()))
	}
	return newNode, nil
}
//Input: rootKey to access a FileNode, location of FileNode
//Output: Deletes data at node.Next and node.ContentPtr recursively
//TODO: 
func deleteLinkedList(rootKey []byte, location uuid.UUID) (error) {
	if (location == uuid.Nil) {
		return nil
	}
	//get the node
	node, e := getNode(rootKey, location)
	if e != nil {
		return errors.New("Error from deleteLinkedList() " + e.Error())
	}
	//delete the content Ptr
	userlib.DatastoreDelete(node.ContentPtr)
	//delete the rest
	deleteLinkedList(node.RootKey, node.Next)
	//delete current node on the datastore
	userlib.DatastoreDelete(location)
	return nil
}
//Input:  symmetric keys and the location of the node
//Output: the node at the specified location
func getNode(rootKey []byte, location uuid.UUID) (FileNode, error) {
	var node = FileNode{}
	serialBytes, gotSerialBytes := userlib.DatastoreGet(location)
	if !gotSerialBytes {
		return FileNode{}, errors.New("Error from getNode() could not get serial bytes")
	}
	encryptKey, macKey, err := generateFileNodeKeys(rootKey)
	if err != nil {
		return FileNode{}, errors.New("Error from getNode() " + err.Error())
	}
	err = deserializeData(serialBytes, encryptKey, macKey, &node)
	if err != nil {
		return FileNode{}, errors.New("Error from getNode() " + err.Error())
	}
	return node, nil
}
func saveNode(rootKey []byte, location uuid.UUID, fileNode FileNode) (error) {
	//get the symmetric keys
	encryptKey, macKey, e := generateFileNodeKeys(rootKey)
	if e != nil {
		return errors.New("Error from saveNode() " + e.Error())
	}
	e = serializeData(encryptKey, macKey, location, fileNode)
	if e != nil {
		return errors.New("Error from saveNode() " + e.Error())
	}
	return nil
}

//Input: Pointer to a file and bytes to overwrite the file with
//Output: None
//Side effects: file now represents a file where its content is just the "content" passed in
func overwriteFile(file *File, content []byte) (error) {
	//delete current linked list
	e := deleteLinkedList(file.HeadRootKey, file.Head)
	if e != nil {
		return errors.New("Error from overwriteFile() " + e.Error()) 
	}
	//create a new node with the content
	//Note createNewNode saves the content on the datastore
	newNode, e := createNewNode(content)
	if e != nil {
		return errors.New("Error from overwriteFile() " + e.Error())
	}
	//save the node at a new UUID
	//For a size one linked list Head and Tail must have the same root key!
	file.HeadRootKey = userlib.RandomBytes(KEY_SIZE)
	file.TailRootKey = file.HeadRootKey
	file.Head = uuid.New()
	file.Tail = file.Head
	saveNode(file.HeadRootKey, file.Head, newNode)
	return nil
}
//Input FileReference instance, File instance, isOwner bool flag
//Output: An Error if function fails
//Side effects: file is now saved on the datastore
func saveFile(fr FileReference, file File, isOwner bool) (error) {
	var encryptKey, macKey []byte
	var location uuid.UUID
	var err error
	//get the keys and uuid for the file
	if !isOwner {
		//get the middleman 
		middleman, err := getMiddleMan(fr.RootKey, fr.MiddleManPtr)
		if err != nil {
			return errors.New("Error from saveFile(): " + err.Error())
		}
		encryptKey, macKey, err = generateFileAccessKeys(middleman.RootKey)
		if err != nil {
			return errors.New("Error from saveFile(): " + err.Error())
		}
		location = middleman.FilePtr
	} else {
		encryptKey, macKey, err = generateFileAccessKeys(fr.RootKey)
		if err != nil {
			return errors.New("Error from saveFile(): " + err.Error())
		}
		location = fr.FilePtr
	}
	//save the file
	err = serializeData(encryptKey, macKey, location, file)
	if err != nil {
		return errors.New("Error from saveFile " + err.Error())
	}
	return nil
}

func saveFileReference(fileReference FileReference, user *User) (error) {
	//get the uuid
	hashInput := []byte(user.username + fileReference.filename)
	fileUUID, err := deriveUUID(hashInput)
	if err != nil {
		return errors.New("An error occurred while generating a UUID: " + err.Error())
	}
	//create deterministic rootkey for a file reference using user.rootKey
	rootKey, e := userlib.HashKDF(user.rootKey, []byte(fileReference.filename))
	if e != nil {
		return errors.New("Error from saveFileReference(): " + e.Error())
	}
	rootKey = rootKey[:KEY_SIZE]
	encryptKey, macKey, e := generateFileReferenceKeys(rootKey)
	if e != nil {
		return errors.New("Failed to save File Reference " + e.Error())
	}
	e = serializeData(encryptKey, macKey, fileUUID, fileReference)
	if e != nil {
		return errors.New("Failed to save File Reference " + e.Error())
	}
	return nil
}

// JC: GetFile() by fileRef
// If isOwner, we use the FilePtr to point to the linked list file
// Otherwise, we use the middlemanPtr to find the filePtr then point to the linked list file
//****** This is also a wrong implementation. Just having it for now need to revist when doing AppendFile()******

//Input: UUID pointing to FileReference instance on Datastore, pointer to User struct
//Output: pointer to the FileReference read from the Datastore
//Side effects: None
func fetchFileReference(filename string, userdataptr *User) (FileReference,  error) {
	//create the UUID for the file
	hashInput := []byte(userdataptr.username + filename)
	fileUUID, err := deriveUUID(hashInput)
	userlib.DebugMsg("%s", fileUUID)
	if err != nil {
		return FileReference{}, errors.New("Error from fetchFileReference() failed to derive fileUUID")
	}
	var fileReference = FileReference{}
	//derive file reference root key
	//deterministic rootkey for a file reference using user.rootKey
	rootKey, e := userlib.HashKDF(userdataptr.rootKey, []byte(filename))
	if e != nil {
		return FileReference{}, errors.New("Error from fetchFileReference(): " + e.Error())
	}
	rootKey = rootKey[:KEY_SIZE]
	// get the symmetric keys
	encryptKey, macKey, e := generateFileReferenceKeys(rootKey)
	if e != nil {
		return FileReference{}, errors.New("ERROR from fetchFileReference() " + e.Error())
	}
	serialData, serialDataExists := userlib.DatastoreGet(fileUUID)
	if !serialDataExists {
		return FileReference{}, errors.New("ERROR from fetchFileReference() fileUUID does not contain serial bytes.")
	}
	e = deserializeData(serialData, encryptKey, macKey, &fileReference)
	if e != nil {
		return FileReference{}, errors.New("ERROR from fetchFileReference() " + e.Error())
	}
	fileReference.filename = filename
	return fileReference, nil
}

func fileReferenceOnDatastore(filename string, userdataptr *User) (bool, error) {
	//create the UUID for the file
	hashInput := []byte(userdataptr.username + filename)
	fileUUID, err := deriveUUID(hashInput)
	userlib.DebugMsg("%s", fileUUID)
	if err != nil {
		return false, errors.New("Error from fetchFileReference() failed to derive fileUUID")
	}
	_ , serialDataExists := userlib.DatastoreGet(fileUUID)
	return serialDataExists, nil
}

//CP: For now assume user is the owner (will update function when implementing file sharing)
//this implementation wont work for filesharing just having it here for now
//****** Revisit when doing AppendFile ******
//Input: filename (string)
//Output: A FileReference instance
func createFileReferenceFromScratch(filename string) (FileReference) {
	var fr FileReference = FileReference {
		RootKey: userlib.RandomBytes(KEY_SIZE),
		filename: filename,
		FilePtr: uuid.New(),
		MiddleManPtr: uuid.Nil,
		}
	return fr
}

//Gets the entire content from a linkedlist
func getContent(file File) ([]byte, error) {
	var content []byte
	var nodeUUID = file.Head
	var rootKey = file.HeadRootKey
	for nodeUUID != uuid.Nil {
		//get the node
		fileNode, err := getNode(rootKey, nodeUUID)
		if err != nil {
			return nil, errors.New("Error from getContent() " + err.Error())
		}
		
		//get the serial data
		serialData, retrievedSuccessfully := userlib.DatastoreGet(fileNode.ContentPtr)
		if !retrievedSuccessfully {
			return nil, errors.New("Error from getContent() could not process file")
		}
		//get the symmetric keys for the content
		encryptKey, macKey, err := generateContentKeys(fileNode.RootKey)
		if err != nil {
			return nil, errors.New("Error from getContent() " + err.Error())
		}
		//get the content
		var fileContentPtr *FileContent = &FileContent{}
		err = deserializeData(serialData, encryptKey, macKey, fileContentPtr)
		if err != nil {
			return nil, errors.New("Error from getContent() Could not process file node " + err.Error())
		}
		content = append(content, fileContentPtr.Content...)
		//set up nodeUUID and rootKey to process next node
		nodeUUID = fileNode.Next
		rootKey = fileNode.RootKey
	}
	return content, nil
}

func encryptRootKey(rootKey []byte, publicKey userlib.PKEEncKey) ([]byte, error) {
	//encrypt user rootKey
	ciphertext, e := userlib.PKEEnc(publicKey, rootKey)
	if e != nil {
		return nil, errors.New("Error from encryptSymmetricKeys() could not encrypt root key. " + e.Error())
	}
	return ciphertext, nil
}

//used when owner is sharing
func createMiddleMan(fileReference FileReference) (MiddleMan) {
	var middle = MiddleMan{
		RootKey: fileReference.RootKey,
		FilePtr: fileReference.FilePtr}
	return middle
}

func createInvitation(middleUUID uuid.UUID, keyCipher []byte, signKey userlib.DSSignKey) (Invitation, error) {
	var invite = Invitation{}
	invite.MiddleManPtr = middleUUID
	invite.EncryptedRootKey = keyCipher
	//sign the key ciphertext
	digitalSignature, e := userlib.DSSign(signKey, keyCipher)
	if e != nil {
		return Invitation{}, errors.New("Error from createInvitation() could not sign ciphertext " + e.Error())
	}
	invite.SignatureOfEncryptedRootKey = digitalSignature
	return invite, nil
}

func updateUser(user *User) (error) {
	//get their symmetric keys
	encryptKey, macKey, e := generateUserKeys(user.rootKey)
	if e != nil {
		return errors.New("Error from updateUser() could not generate keys")
	}
	userUUID, e := deriveUUID([]byte(user.username))
	if e != nil {
		return errors.New("Error from updateUser() could not derive UUID")
	}
	e = serializeData(encryptKey, macKey, userUUID, user)
	if e != nil {
		return errors.New("Error from updateUser() could not save user")
	}
	return nil
}

func storeInvitation(invitePtr uuid.UUID, invite Invitation) (error) {
	//marshal the data
	serialBytes, e := json.Marshal(invite)
	if e != nil {
		return errors.New("Error from storeInvite() " + e.Error())
	}
	userlib.DatastoreSet(invitePtr, serialBytes)
	return nil
}

func retrieveInvite(invitationPtr uuid.UUID, sender string) (Invitation, error) {
	serialBytes, gotSerialBytes := userlib.DatastoreGet(invitationPtr)
	if !gotSerialBytes {
		return Invitation{}, errors.New("Error from storeInvite() could not get serial bytes.")
	}
	var invite = Invitation{}
	e := json.Unmarshal(serialBytes, &invite)
	if e != nil {
		return Invitation{}, errors.New("Error from storeInvite() " + e.Error())
	}
	//check the digital signature
	verifyKey, gotVerifyKey := userlib.KeystoreGet(fmt.Sprint(sender, VERIFY_SUFFIX))
	if !gotVerifyKey {
		return Invitation{},  errors.New("Error from storeInvite() could not get sender's verify key")
	}
	e = userlib.DSVerify(verifyKey, invite.EncryptedRootKey, invite.SignatureOfEncryptedRootKey)
	if e != nil {
		return Invitation{},  errors.New("Error from storeInvite() " + e.Error())
	}
	return invite, nil
}

func checkMAC(macKey []byte, secureDataPtr uuid.UUID) (error) {
	var secureData *SecureData = &SecureData{}
	serialBytes, gotTheBytes := userlib.DatastoreGet(secureDataPtr)
	if !gotTheBytes {
		return errors.New("Error from checkMAC() could not get bytes from datastore")
	}
	e := json.Unmarshal(serialBytes, secureData)
	if e != nil {
		return errors.New("Error from checkMAC() " + e.Error())
	}
	//check the HMACs
	testMac, e := userlib.HMACEval(macKey, secureData.Ciphertext)
	if e != nil {
		return errors.New("Error from checkMAC() " + e.Error())
	}
	if !userlib.HMACEqual(testMac, secureData.Mac) {
		return errors.New("Error from checkMAC() the MACs do not match.")
	}
	return nil
}
//Input: File to copy
//Output: Copied file, an error (if function fails)
//Side effects: Previous file content is deleted from datastore (Note the actual file struct is still there!)
//new file contents placed on datastore
func fileDeepCopy(file File) (File, error){
	//1) read all the content
	content, err := getContent(file)
	if err != nil {
		return File{}, errors.New("Error from file deep copy " + err.Error())
	}
	//2) delete the old file
	err = deleteLinkedList(file.HeadRootKey, file.Head)
	if err != nil {
		return File{}, errors.New("Error from file deep copy " + err.Error())
	}
	//create a new file using previous content of last file
	var newFile File
	err = overwriteFile(&newFile, content)
	if err != nil {
		return File{}, errors.New("Error from file deep copy " + err.Error())
	}
	return newFile, nil
}

//Input: owner's file reference
//Output: An error (Not nil if successful)
//Side effects: Old file is deleted, new file is returned having the same content as the old file
func createNewFileFromOldFile(fr FileReference) (File, error) {
	//need to create a brand new copy of the file with new keys
	//1) Fetch the file and create a new copy with new keys given
	file, e := getFile(fr, true)
	if e != nil {
		return File{}, errors.New("Error from updateAccessRights() " + e.Error())
	}
	//create a new copy of the file with new keys
	newFile, e := fileDeepCopy(file)
	if e != nil {
		return File{}, errors.New("Error from updateAccessRights() " + e.Error())
	}
	//delete the old file
	userlib.DatastoreDelete(fr.FilePtr)
	return newFile, nil
}
//FileNames
//Input: person to revoke access from, pointer to owner's FileReference, the NewFile to store
//Output: error if function fails
//Side effect: Users middleman list is updated, all middleman who should maintain access are given new keys
func updateAccessRights(revokee string, fr *FileReference, newFile File, userRootKey []byte) (error) {
	//1) delete old file of owner
	userlib.DatastoreDelete(fr.FilePtr)
	//2) create new rootkey for the new file and a new UUID to store the new file at
	newRootKey := userlib.RandomBytes(KEY_SIZE)
	newFileUUID := uuid.New()
	fr.RootKey = newRootKey
	fr.FilePtr = newFileUUID
	//3)get the sharing map
	sharingMap, err := getSharingMap(userRootKey, *fr) 
	if err != nil {
		return errors.New("Error from updateAccessRights() " + err.Error())
	}
	//4) go through list of middleman and update root keys of those who should maintain access
	for recipient, middleManEntry := range sharingMap.MiddleManMap {
		if recipient != revokee {
			middleman, err := getMiddleMan(middleManEntry.RootKey, middleManEntry.MiddleManPtr)
			if err != nil {
				return errors.New("Error from updateAccessRights() " + err.Error())
			}
			//update middleman keys
			middleman.RootKey = newRootKey
			middleman.FilePtr = newFileUUID
			//store updated middleman on the datastore
			//1) get the keys
			encryptKey, macKey, err := generateMiddleManKeys(middleManEntry.RootKey)
			if err != nil {
				return errors.New("Error from updateAccessRights() " + err.Error())
			}
			//2)save middleman on datastore
			err = serializeData(encryptKey, macKey, middleManEntry.MiddleManPtr, middleman)
			if err != nil {
				return errors.New("Error from updateAccessRights() " + err.Error())
			}
		} else {
			//delete recipient's middleman
			userlib.DatastoreDelete(middleManEntry.MiddleManPtr)

		} 
	}
	//remove recipient from the map
	delete(sharingMap.MiddleManMap, revokee)
	err = saveSharingMap(userRootKey, *fr, sharingMap)
	if err != nil {
		return errors.New("Error from updateAccessRights() " + err.Error())
	}
	return nil
}

//Input: File obj, node to be appended
//Output: error if function fails
//Side effects appends new Node to linked list and saves the changes to the nodes
//Updates file (still need to save it)
func appendToFile(file *File, nodeToAppend FileNode) (error) {
	//1) read the tail node to get the new TailRootKey
	//(the last node will be able to uncover the node that is appended)
	oldTailNode, err := getNode(file.TailRootKey, file.Tail)
	if err != nil {
		return errors.New("Error from appendToFile() " + err.Error())
	}
	//append a node to the old tail node
	newNodeUUID := uuid.New()
	oldTailNode.Next = newNodeUUID
	//save changes to old tail node 
	err = saveNode(file.TailRootKey, file.Tail, oldTailNode)
	if err != nil {
		return errors.New("Error from appendToFile() " + err.Error())
	}
	//save new tail node on the datastore
	err = saveNode(oldTailNode.RootKey, newNodeUUID, nodeToAppend)
	if err != nil {
		return errors.New("Error from appendToFile() " + err.Error())
	}
	//have the TailRootKey be the root key of the old tail node (this key accesses the last node)
	file.Tail = newNodeUUID
	file.TailRootKey = oldTailNode.RootKey
	return nil
}

//////////////////////////////////****** Project Functions start ******//////////////////////////////////
func InitUser(username string, password string) (*User, error) {
	var userdata User
	var userdataptr *User = &userdata
	if len(username) == 0 {
		return nil, errors.New("Error from InitUser(): Username can't be empty")
	}
	userdataptr.username = username
	//generate a UUID using a Hash(username) (want to use username if its 1 or 100 bytes long)
	userUUID, e := deriveUUID([]byte(username))
	if e != nil {
		return nil, e
	}
	if _, hasPublicKey := userlib.KeystoreGet(fmt.Sprint(username, PK_SUFFIX)); hasPublicKey  {
		return nil, errors.New(fmt.Sprint("ERROR from InitUser() : can't create user:", username, ", username is taken."))
	}
	//create a rootKey to associate with the user
	userHash := userlib.Hash([]byte(username))[:UUID_SIZE]
	rootKey := userlib.Argon2Key([]byte(password), userHash, uint32(KEY_SIZE))
	userdataptr.rootKey = rootKey
	if e != nil {
		return nil, e
	}
	//create the neccessary symmetric keys
	encryptKey, macKey, e := generateUserKeys(rootKey)
	if e != nil {
		return nil, e
	}
	//generate the necessary public keys
	e = generatePublicKeys(userdataptr)
	if e != nil {
		return nil, e
	}
	//encrpyt-then-MAC the User struct
	e = serializeData(encryptKey, macKey, userUUID, userdataptr)
	if e != nil {
		return nil, e
	}
	return userdataptr, nil
}


func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	if _, hasPublicKey := userlib.KeystoreGet(fmt.Sprint(username, PK_SUFFIX)); !hasPublicKey {
		return nil, errors.New("Error from GetUser(): User not initialized.")
	}
	userdataptr.username = username
	userUUID, err := deriveUUID([]byte(username))
	if err != nil {
		return nil, err
	}
	var serialData, hasValue = userlib.DatastoreGet(userUUID)
	if !hasValue {
		return nil, errors.New("Error from GetUser(): UUID does not point to data.")
	}
	//create a rootKey to associate with the user
	userHash := userlib.Hash([]byte(username))[:UUID_SIZE]
	rootKey := userlib.Argon2Key([]byte(password), userHash, uint32(KEY_SIZE))
	userdataptr.rootKey = rootKey
	if err != nil {
		return nil, errors.New("Error from GetUser() " + err.Error())
	}

	//retrieve the serialized data
	encryptKey, macKey, e := generateUserKeys(rootKey)
	if e != nil {
		return userdataptr, errors.New("Error from GetUser(): " + e.Error())
	}
	e = deserializeData(serialData, encryptKey, macKey, userdataptr)
	if e != nil {
		return nil, errors.New("Error from GetUser(): " + e.Error())
	}
	return userdataptr, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (error) {
	var fileReference FileReference
	var err error
	var file File
	var userOwnership bool
	//CP: Check if the file already exists
	fileExists, err := fileReferenceOnDatastore(filename, userdata)
	if err != nil {
		return errors.New("ERROR from StoreFile(): " + err.Error())
	}
	if fileExists {
		fileReference, err = fetchFileReference(filename, userdata)
		if err != nil {
			return errors.New("ERROR from StoreFile(): " + err.Error())
		}
		userOwnership = fileReference.FilePtr != uuid.Nil
	}
	var isOwner bool
	if !fileExists {
		//user is creating file for the first time thus their the owner
		isOwner = true
		fileReference = createFileReferenceFromScratch(filename)
		//save an empty sharingMap
		err = saveSharingMap(userdata.rootKey, fileReference, SharingMap{make(map[string]MiddleManEntry)})
		if err != nil {
			return errors.New("ERROR from StoreFile(): " + err.Error())
		}
	} else {
		isOwner = userOwnership
		if err != nil {
			return errors.New("ERROR from StoreFile(): " + err.Error())
		}
		file, err = getFile(fileReference, isOwner)
		if err != nil {
			return errors.New("ERROR from StoreFile(): " + err.Error())
		}
	}
	//clear File contents and add the new content
	overwriteFile(&file, content)
	//Need to update Datastore by serializing values that were changed: File, FileReference (cover case when created)
	err = saveFile(fileReference, file, isOwner)
	if err != nil {
		return errors.New("ERROR from StoreFile(): " + err.Error())
	}
	err = saveFileReference(fileReference, userdata)
	if err != nil {
		return err
	}
	return nil
}

//FileNames
func (userdata *User) AppendToFile(filename string, content []byte) error {
	//Fetch file reference should take care of filename not being in namespace
	//retrieval depends on it being so
	//***** fetching file depends on number of reads will fix******
	fileRef, err := fetchFileReference(filename, userdata)
	if err != nil  {
		return errors.New("Error from AppendToFile(): " + err.Error())
	}
	//get the ownership
	var isOwner bool = fileRef.FilePtr != uuid.Nil
	//get access to the file object
	file, err := getFile(fileRef, isOwner)
	if err != nil {
		return errors.New("Error from AppendToFile(): " + err.Error())
	}
	//1) create a new FileNode (Note createNewNode stores content on datastore for us)
	var nodeToAppend FileNode
	nodeToAppend, err = createNewNode(content)
	if err != nil {
		return errors.New("Error from AppendToFile(): " + err.Error())
	}
	//2) append content to the file
	err = appendToFile(&file, nodeToAppend)
	if err != nil {
		return errors.New("Error from AppendToFile(): " + err.Error())
	}
	//3) save the file
	err = saveFile(fileRef, file, isOwner)
	if err != nil {
		return errors.New("Error from AppendToFile(): " + err.Error())
	}
	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	var fileReference FileReference
	var file File
	var e error
	//fetch the file reference (this covers the namespace check!)
	fileReference, e = fetchFileReference(filename, userdata)
	if e != nil {
		return nil, errors.New("Error: could not fetch file reference " + e.Error())
	}
	var ownership bool = (fileReference.FilePtr != uuid.Nil)
	//fetch the file itself
	file, e = getFile(fileReference, ownership)
	if e != nil {
		return nil, errors.New("Error: Could not get the file " + e.Error())
	}
	//get the contents of the file
	content, e = getContent(file)
	if e != nil {
		return nil, errors.New(fmt.Sprint("Could not retrieve file content ", e.Error()))
	}
	return content, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	var invitationUUID = uuid.New()
	//check recipient is valid by attempting to get its publicKey (all users should have a public key)
	publicKey, retrievedSuccessfully := userlib.KeystoreGet(fmt.Sprint(recipientUsername, PK_SUFFIX))
	if !retrievedSuccessfully {
		return uuid.Nil, errors.New("Error from CreateInvitation() recipient does not exist")
	}
	//need to fetch the keys to tack on to the invitation
	//also this covers the namespace check!
	fr, err := fetchFileReference(filename, userdata)
	if err != nil {
		return uuid.Nil, errors.New("ERROR from CreateInvitation(): " + err.Error())
	}
	//get the ownership
	var isOwner = (fr.FilePtr != uuid.Nil)
	
	//rootKey for accessing the middleman
	var rootKey[]byte
	var middleUUID uuid.UUID
	if isOwner {
		middleUUID = uuid.New()
		middleMan := createMiddleMan(fr)
		//create keys for storing middleman on the datastore
		rootKey = userlib.RandomBytes(KEY_SIZE)
		//save the middleman on the datastore
		encryptKey, macKey, err := generateMiddleManKeys(rootKey)
		if err != nil {
			return uuid.Nil, errors.New("Error from CreateInvitation(): " + err.Error())
		}
		err = serializeData(encryptKey, macKey, middleUUID, middleMan)
		if err!= nil {
			return uuid.Nil, errors.New("ERROR from CreateInvitation(): " + err.Error())
		}
		//get the sharingMap
		sharingMap, err := getSharingMap(userdata.rootKey, fr)
		if err != nil {
			return uuid.Nil, errors.New("Error from CreateInvitation(): " + err.Error())
		}
		//add middleman entry to the user's middleman list for revocation purposes
		//Note will need to save file reference on the datastore to reflect a change in one of its fields
		middleEntry := MiddleManEntry {
			MiddleManPtr: middleUUID,
			RootKey: rootKey}
		sharingMap.MiddleManMap[recipientUsername] =  middleEntry
		//need to save sharingMap
		err = saveSharingMap(userdata.rootKey, fr, sharingMap)
		if err != nil {
			return uuid.Nil, errors.New("Error from CreateInvitation(): " + err.Error())
		}
	} else {
		//middleman already on datastore no need to save it 
		rootKey = fr.RootKey
		middleUUID = fr.MiddleManPtr
	}
	keyCipher, err := encryptRootKey(rootKey, publicKey)
	if err != nil {
		return uuid.Nil, errors.New("Error from CreateInvitation(): " + err.Error())
	}
	invitation, err := createInvitation(middleUUID, keyCipher, userdata.SigningKey)
	if err != nil {
		return uuid.Nil, errors.New("Error from CreateInvitation(): " + err.Error())
	}
	err = storeInvitation(invitationUUID, invitation)
	if err != nil {
		return uuid.Nil, errors.New("Error from CreateInvitation(): " + err.Error())
	}
	return invitationUUID, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	//Check if user already has file in namespace
	fileOnDatastore, err := fileReferenceOnDatastore(filename, userdata)
	if err != nil || fileOnDatastore{
		return errors.New("Error from AcceptInvitation: " + err.Error())
	}
	//get and verify signature
	invite, err := retrieveInvite(invitationPtr, senderUsername)
	if err != nil {
		return errors.New("Error from AcceptInvitation: " + err.Error())
	}
	//decrypt the rootKey
	rootKey, err := userlib.PKEDec(userdata.DecryptRSA, invite.EncryptedRootKey)
	if err != nil {
		return errors.New("Error from AcceptInvitation: " + err.Error())
	}
	_, macKey, err := generateMiddleManKeys(rootKey)
	//check the HMAC on the ciphertext
	userlib.DebugMsg("Hello World")
	err = checkMAC(macKey, invite.MiddleManPtr)
	if err != nil {
		return errors.New("Error from AcceptInvitation: " + err.Error())
	}
	//If execution made it this far everything checks out! Create a file reference for the user and save it
	var fileReference = FileReference {
		RootKey: rootKey,
		filename : filename,
		MiddleManPtr : invite.MiddleManPtr,
		FilePtr : uuid.Nil}

	//save the new file reference and the updated user
	err = saveFileReference(fileReference, userdata)
	if err != nil {
		return errors.New("Error from AcceptInvitation: " + err.Error())
	}
	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	//get the file reference of the owner
	//if it fails file not in users namespace
	fr, err := fetchFileReference(filename, userdata)
	if err != nil {
		return errors.New("ERROR from RevokeAccess(): " + err.Error())
	}
	//get the sharing map
	sharingMap, err := getSharingMap(userdata.rootKey, fr)
	//check file is actually shared with recipient
	_, isSharedWith := sharingMap.MiddleManMap[recipientUsername]
	if !isSharedWith {
		return errors.New("ERROR from RevokeAccess(): file not shared with " + recipientUsername)
	}
	//create a new copy of the file to securely store
	newFile, err := createNewFileFromOldFile(fr)
	if err != nil {
		return errors.New("ERROR from RevokeAccess(): " + err.Error())
	}
	//update the access rights
	err = updateAccessRights(recipientUsername, &fr, newFile, userdata.rootKey)
	if err != nil {
		return errors.New("ERROR from RevokeAccess(): " + err.Error())
	}
	//save the updated file
	err = saveFile(fr, newFile, true)
	if err != nil {
		return errors.New("ERROR from RevokeAccess(): " + err.Error())
	}
	//save the updated file reference
	err = saveFileReference(fr, userdata)
	if err != nil {
		return errors.New("ERROR from RevokeAccess(): " + err.Error())
	}
	return nil
}
