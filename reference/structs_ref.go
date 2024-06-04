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
