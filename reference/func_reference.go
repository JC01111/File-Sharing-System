// Function reference
// Format: Function name, Input, Output


func generateSymmetricKeys(rootKey []byte, encryptPurpose []byte, macPurpose []byte) (encryptKey []byte, macKey []byte, err error)
Input: Takes a user's rootKey and two purposes (some sequence of bytes)
Output: Produces two symmetric keys. One for encryption the other for MACing. A return error to indicate function failed
Side effects: None


func deriveUUID(val []byte) (uuid.UUID, error)
Input: val a byte sequence used to produce a UUID
Output: The uuid generated. Returns error to indicate function failed
Side Effects: None


func generatePublicKeys(user *User) (err error)
Input: user is a Pointer to a user
Output: Error if function fails
Side effects: creates two RSA keypairs. One for RSA encryption the other for signing.
user struct stores its private keys at the end of the function
user's public keys put on the keystor


func serializeData(encryptKey []byte, macKey []byte, userUUID uuid.UUID, data interface{}) (err error)
Input: the two symmetric keys to encrypt-then-MAC, a uuid to store serialized data at a data object to serialize
Output: Returns an error if function fails
Side effects: obj is serialized and then Encrypt-then-MAC is performed on the serialize bytes
Result stored in a SecureData struct which is then serialized and put in the Datastore


func deserializeData(serialData []byte, encryptKey []byte, macKey []byte, obj interface{}) (e error)
Input: serial data (Should represent a Secure Data object!), two symmetric keys for Encrypt-then-MAC, obj should be a pointer to an object
Output: An error if the function fails
Side effects: obj should now point to an object of it's type retrieved from Datastore


//If isOwner is true then user.EncryptKey, user.MacKey correspond to the keys to access the File obj
//Else keys correspond to the MiddleMan on the Datastore
func getFile(fileRef FileReference, isOwner bool) (File, error)
Input: a FileReference instance, isOwner boolean flag to indicate ownership
Returns: File obj from datastore
Side effects: None


func createNewNode(content []byte) (*FileNode, error)
//creates a new node and stores the content on the datastore
Input: content to store in node
Output: pointer to new file node
Side effects: content of new node stored on datastore


func overwriteFile(file *File, content []byte)
Input: Pointer to a file and bytes to overwrite the file with
Output: None
Side effects: file now represents a file where its content is just the "content" passed in


func saveFile(fr FileReference, file File, isOwner bool) (error)
Input FileReference instance, File instance, isOwner bool flag
Output: An Error if function fails
Side effects: file is now saved on the datastore


func saveFileReference(fileReference FileReference, user *User) (error)
Input: fileReference, user
Output: error if can't save file
Side effects: save the fileReference into Datastore


//****** This is also a wrong implementation. Just having it for now need to revist when doing AppendFile()******
func fetchFileReference(fileUUID uuid.UUID, userdataptr *User) (*FileReference, error)
Input: UUID pointing to FileReference instance, pointer to User struct
Output: pointer to the FileReference read from the Datastore, An error if function fails
Side effects: None


//CP: For now assume user is the owner (will update function when implementing file sharing)
//this implementation wont work for filesharing just having it here for now
//****** Revisit when doing AppendFile ******
func createFileReference(filename string) (FileReference, error)
Input: filename (string)
Output: A FileReference instance
