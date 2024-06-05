package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"
const contentFour = "pizza"
const contentFive = "tree"
const contentSix = "giraffe"
const aliceContent = "Alice's content"
const bobContent = "Bob's content"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	var christian *client.User
	var jay *client.User
	var doris *client.User
	var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User
	// JAY TESTING
	var bobLaptop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	aliceSecondFile := "alice2ndFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	christianFile := "christian.txt"
	jayFile := "jay.txt"
	dorisFile := "dorisFile.txt"
	eveFile := "eveFile.txt"
	commonFile := "commonFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice again.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})


		Specify("Basic Test: Testing Single User Store/Load.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))
		})

		Specify("Basic Test: Testing Single User Store/Load/Append one operation each.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))


		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

	})

	Describe("Edge Case Tests", func() {
		Specify("Edge case: Testing initUser on same username.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword + defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Edge case: Testing Revoking before accepting invite", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing content at " + aliceFile)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating Invitation for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's invite.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invite.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Edge case: Creating sharing tree and revoking the access of a subtree", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Christian.")
			christian, err = client.InitUser("christian", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Jay.")
			jay, err = client.InitUser("jay", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Doris.")
			doris, err = client.InitUser("doris", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Eve.")
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating file to be shared")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating sharing tree...")
			//					Alice
			//					/	\
			//				   / 	 \
			//			 	bob	   	christian
			//			   /	\			\
			//			  /		 \			 \
			//			doris	eve			 jay

			userlib.DebugMsg("Alice creating Invitation for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invite.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating Invitation for Doris.")
			invite, err = bob.CreateInvitation(bobFile, "doris")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris accepting Bob's invite.")
			err = doris.AcceptInvitation("bob", invite, dorisFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating Invitation for Eve.")
			invite, err = bob.CreateInvitation(bobFile, "eve")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve accepting Bob's invite.")
			err = eve.AcceptInvitation("bob", invite, eveFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating Invitation for Christian.")
			invite, err = alice.CreateInvitation(aliceFile, "christian")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Christian accepting Alice's invite.")
			err = christian.AcceptInvitation("alice", invite, christianFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Christian creating Invitation for Jay.")
			invite, err = christian.CreateInvitation(christianFile, "jay")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Jay accepting Christian's invite.")
			err = jay.AcceptInvitation("christian", invite, jayFile)
			Expect(err).To(BeNil())

			//Have users mess with the file a little
			userlib.DebugMsg("Appending file data %s", contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Christian loading file content.")
			data, err := christian.LoadFile(christianFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo)))

			userlib.DebugMsg("Jay storing file with %s.", contentThree)
			err = jay.StoreFile(jayFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking access from Bob")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Doris attempting to load the file")
			data, err = doris.LoadFile(dorisFile)
			Expect(err).ToNot(BeNil())
			Expect(data).ToNot(Equal([]byte(contentThree)))

			userlib.DebugMsg("Eve attempting to append to the file")
			err = eve.AppendToFile(eveFile, []byte(contentFour))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Christian attempting to load the file")
			data, err = christian.LoadFile(christianFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Alice attempting to load the file")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree)))

			userlib.DebugMsg("Jay appending to file with %s.", contentFour)
			err = jay.AppendToFile(jayFile, []byte(contentFour))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Christian attempting to load the file")
			data, err = christian.LoadFile(christianFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentThree + contentFour)))

		})

		Specify("Edge case test: creating a user with an empty username", func() {
			userlib.DebugMsg("Initializing user \"\".")
			_, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Edge case test: getting a user that doesn't exist", func() {
			userlib.DebugMsg("Getting user Alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			Expect(alice).To(BeNil())
		})

		Specify("Edge case test: User already has file in namespace when accepting invitation.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating file for Alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating file for Bob")
			err = bob.StoreFile(bobFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating Invitation for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invite using filename already in namespace.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Edge case test: User is revoking access to a file not in their namespace.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating file for Alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating Invitation for Bob.")
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invite using filename already in namespace.")
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice attempting to revoke access for file not in namespace.")
			err = alice.RevokeAccess(aliceSecondFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Edge case test: User is revoking access to a file not shared to the recipient.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Creating file for Alice")
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())


			userlib.DebugMsg("Alice attempting to revoke access for file not shared to Bob.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Edge case test: Invalid credentials are provided in GetUser", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Malicious user trying to log in as Alice.")
			aliceLaptop, err = client.InitUser("alice", defaultPassword + contentOne)
			Expect(err).ToNot(BeNil())

		})
	})


	// Jay testing
	Describe("Advanced Tests", func() {
		Specify("Advanced Test: Testing InitUser/GetUser with multiple instances and users.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Bob.")
			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Comparing Alice and AliceLaptop.")
			Expect(alice).ToNot(Equal(aliceLaptop))

			userlib.DebugMsg("Comparing Bob and BobLaptop.")
			Expect(bob).ToNot(Equal(bobLaptop))

			userlib.DebugMsg("Checking Alice and Bob are different.")
			Expect(alice).ToNot(Equal(bob))
	})

		Specify("Advanced Test: Testing Multi User Store/Load/Append with permissions.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to append file data with unauthorized user: %s", contentTwo)
			err = bob.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil()) // Error should not be nil, because Bob should not be authorized

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne))) // Alice file content should not change
	})

		Specify("Advanced Test: Testing Multiple Invitations and Revokes", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charles.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob and Charles for file %s.", aliceFile)
			inviteBob, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			inviteCharles, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob and Charles accepting invite from Alice under filenames %s and %s.", bobFile, charlesFile)
			err = bob.AcceptInvitation("alice", inviteBob, bobFile)
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("alice", inviteCharles, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob and Charles can load the file.")
			dataBob, err := bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(dataBob).To(Equal([]byte(contentOne)))

			dataCharles, err := charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(dataCharles).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Bob lost access to the file but Charles didn't.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			dataCharles, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(dataCharles).To(Equal([]byte(contentOne)))
	})
})


	Describe("Advanced AppendToFile Tests", func() {
		Specify("Advanced Test: Testing AppendToFile with Unauthorized User", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Eve.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			// Eve is unauthorized user
			eve, err = client.InitUser("eve", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Eve (unauthorized) trying to append to Alice's file")
			err = eve.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil()) // expect error since Eve is unauthorized

			userlib.DebugMsg("Checking that Alice's file has not been changed.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne))) // The file should not have changed
})

		Specify("Advanced Test: Testing AppendToFile with Shared Users", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)
			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can see Bob's changes.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo))) // Alice should see the changes made by Bob
})

		Specify("Advanced Test: Testing AppendToFile to Prevent Version History", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Attempting to load old version of file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).ToNot(Equal([]byte(contentOne))) // Loading file should not return old version
			Expect(data).ToNot(Equal([]byte(contentOne + contentTwo))) // Loading file should not return older version
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree))) // Loading file should return the latest version
		})
})
	// Simple Storing and swapping users
	Describe("File Store and Swap Tests", func() {
		Specify("Testing Storing and Swapping Users on the Datastore", func() {
			//get the datastore
			datastore := userlib.DatastoreGetMap()
			userlib.DebugMsg("Initializing users Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(alice).ToNot(BeNil())
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Bob.")
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())
			Expect(bob).ToNot(BeNil())

			var aliceUUID, bobUUID [16]byte
			var aliceUUIDBytes []byte = []byte("\x40\x8b\x27\xd3\x09\x7e\xea\x5a\x46\xbf\x2a\xb6\x43\x3a\x72\x34")
			bobUUIDBytes := []byte("\x04\x16\xa2\x6b\xa5\x54\x33\x42\x86\xb1\x95\x49\x18\xec\xad\x7b")
			copy(aliceUUID[:], aliceUUIDBytes)
			copy(bobUUID[:], bobUUIDBytes)
			//Swapping data
			aliceData, gotBytes := datastore[aliceUUID]
			Expect(gotBytes).To(Equal(true))

			bobData, gotBytes := datastore[bobUUID]
			Expect(gotBytes).To(Equal(true))
			userlib.DebugMsg("Swapping user data on the datastore")
			userlib.DatastoreGetMap()[aliceUUID] = bobData
			userlib.DatastoreGetMap()[bobUUID] = aliceData

			//attempt to retrieve user now
			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
			Expect(aliceLaptop).To(BeNil())
			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			bobLaptop, err = client.GetUser("bob", defaultPassword)
			Expect(err).ToNot(BeNil())
			Expect(bobLaptop).To(BeNil())
		})
	})

	Describe("Tampering with users files", func() {
		Specify("Swapping files on the Datastore", func() {
			//get the datastore
			datastore := userlib.DatastoreGetMap()
			userlib.DebugMsg("Initializing users Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())


			userlib.DebugMsg("Alice creating %s.", aliceFile)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())


			userlib.DebugMsg("Alice creating %s.", aliceSecondFile)
			err = alice.StoreFile(aliceSecondFile, []byte(contentTwo))
			Expect(err).To(BeNil())


			aliceFileUUIDBytes := []byte("\xb0\x03\x99\x6f\x2a\x93\x36\x11\x2b\x63\x68\x3d\x85\x57\x51\xce")
			aliceSecondFileUUIDBytes := []byte("\x2b\x15\xb2\x41\xa7\x39\x07\x93\xa0\x5f\x30\x70\x3e\x50\x67\xde")
			var aliceFileUUID, aliceFile2UUID [16]byte
			copy(aliceFileUUID[:], aliceFileUUIDBytes)
			copy(aliceFile2UUID[:], aliceSecondFileUUIDBytes)

			//check can access the datastore
			aliceFileData, gotTheBytes := datastore[aliceFileUUID]
			Expect(gotTheBytes).To(Equal(true))
			aliceFile2Data, gotTheBytes := datastore[aliceFile2UUID]
			Expect(gotTheBytes).To(Equal(true))

			userlib.DebugMsg("Datastore adversary swapping file data on the datastore...")
			datastore[aliceFileUUID] = aliceFile2Data
			datastore[aliceFile2UUID] = aliceFileData

			userlib.DebugMsg("Alice attempting to load file content from %s", aliceFile)
			data, err := alice.LoadFile(aliceFile)
			Expect(data).ToNot(Equal([]byte(contentOne)))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice attempting to append to the file %s", aliceSecondFile)
			err = alice.AppendToFile(aliceSecondFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Alice attempting to Store to the file %s", aliceFile)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

		})
	})

	// Simple Storing and swapping files tests
	Describe("File Store and Swap Tests", func() {
		Specify("Testing Storing and Swapping Files with the Same Names", func() {
			userlib.DebugMsg("Initializing users Alice.")
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())
			userlib.DebugMsg("Initializing user Bob.")
			bob, err := client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice and Bob storing files with the same name: %s", commonFile)
			err = alice.StoreFile(commonFile, []byte(aliceContent))
			Expect(err).To(BeNil())

			err = bob.StoreFile(commonFile, []byte(bobContent))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice and Bob swapping their files.")
			// Alice tries to load Bob's file
			aliceAttempt, err := alice.LoadFile(commonFile)
			Expect(err).To(BeNil())
			Expect(aliceAttempt).To(Equal([]byte(aliceContent))) // Alice should only see her file

			// Bob tries to load Alice's file
			bobAttempt, err := bob.LoadFile(commonFile)
			Expect(err).To(BeNil())
			Expect(bobAttempt).To(Equal([]byte(bobContent))) // Bob should only see his file
		})
	})
	// Enhanced Version
	Describe("Storing and Swapping Files Tests", func() {
		Specify("Test: Storing Files with Same Name by Different Users and Swapping", func() {
			userlib.DebugMsg("Initializing users Alice and Bob.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", commonFile, aliceContent)
			err = alice.StoreFile(commonFile, []byte(aliceContent))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", commonFile, bobContent)
			err = bob.StoreFile(commonFile, []byte(bobContent))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", commonFile, "bobCommonFile")
			invite, err := alice.CreateInvitation(commonFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, "bobCommonFile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob creating invite for Alice for file %s, and Alice accepting invite under name %s.", commonFile, "aliceCommonFile")
			invite, err = bob.CreateInvitation(commonFile, "alice")
			Expect(err).To(BeNil())

			err = alice.AcceptInvitation("bob", invite, "aliceCommonFile")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice's original file has not been changed.")
			data, err := alice.LoadFile(commonFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(aliceContent)))

			userlib.DebugMsg("Checking that Bob's original file has not been changed.")
			data, err = bob.LoadFile(commonFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(bobContent)))

			userlib.DebugMsg("Checking that Alice can access Bob's file under name %s.", "aliceCommonFile")
			data, err = alice.LoadFile("aliceCommonFile")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(bobContent)))

			userlib.DebugMsg("Checking that Bob can access Alice's file under name %s.", "bobCommonFile")
			data, err = bob.LoadFile("bobCommonFile")
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(aliceContent)))
	})
})


	// trying to mess with DatastoreGetMap() and KeystoreGetMap()
	Describe("Advanced Tests", func() {

		Specify("Advanced Test: Check the integrity of the Datastore", func() {
			// Initialize a user Alice.
			alice, err := client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			// Store some data into a file.
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			// Check the data in the datastore
			datastore := userlib.DatastoreGetMap()

			userlib.DebugMsg("Datastore is not Empty after storing file")
			// There should be at least one item in the datastore after storing the file
			Expect(len(datastore)).To(BeNumerically(">", 0))


			// // Get the FileUUID
			// hashInput := []byte("alice" + aliceFile)
			// userHash := userlib.Hash(hashInput)[:UUID_SIZE]
			// fileUUID, err := uuid.FromBytes(userHash)
			// Expect(err).To(BeNil())
			//
			// // Check if alice's file data exists in the datastore
			// _, ok := userlib.DatastoreGet(fileUUID)
			// Expect(ok).To(BeTrue()) // The key should exist in the datastore
			//
			// // Now delete the file data from the datastore and validate it's deletion
			// userlib.DatastoreDelete(fileUUID)
			//
			// // Check if the file data is deleted from the datastore
			// userlib.DebugMsg("Datastore is Empty after delete file")
			// datastore = userlib.DatastoreGetMap()
			// _, ok = userlib.DatastoreGet(fileUUID)
			// Expect(ok).To(BeFalse()) // The key should not exist in the datastore after deletion
		})

		// Specify("Advanced Test: Check the integrity of the Keystore", func() {
		// 	// Initialize a user Alice.
		// 	alice, err := client.InitUser("alice", defaultPassword)
		// 	Expect(err).To(BeNil())
		//
		// 	// The user's public key should have been added to the keystore during initialization.
		// 	keystore := userlib.KeystoreGetMap()
		//
		// 	// Alice's public key should exist in the keystore
		// 	aliceKey, ok := userlib.KeystoreGet(alice)
		// 	Expect(ok).To(BeTrue())
		//
		// 	// Now initialize another user Bob.
		// 	bob, err := client.InitUser("bob", defaultPassword)
		// 	Expect(err).To(BeNil())
		//
		// 	// Bob's public key should also be added to the keystore.
		// 	bobKey, ok := userlib.KeystoreGet(bob)
		// 	Expect(ok).To(BeTrue())
		//
		// 	// Test the KeystoreSet method by setting a new key for Bob
		// 	newKey := userlib.GeneratePublicPrivatePair().Public
		// 	err = userlib.KeystoreSet(bob, newKey)
		// 	Expect(err).NotTo(BeNil()) // Should return an error because existing key cannot be overwritten
		//
		// 	// Bob's key should not be changed in the keystore
		// 	currentBobKey, _ := userlib.KeystoreGet(bob)
		// 	Expect(currentBobKey).To(Equal(bobKey))
		// })
})








})
