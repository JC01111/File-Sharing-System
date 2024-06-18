# File Sharing System
<p align="center">
<img src="./images/spying2.png" width=700>

## Overview
In this project,I used some provide cryptographic library functions to design a secure file sharing system, which will allow users to log in, store files, and share files with other users, while in the presence of attackers. Then, I implemented my design by filling in 8 functions that users of my system can call to perform file operations.

This project is heavily design-oriented. So I started with a design from scratch that satisfies the functionality and security requirements.

Look at [client.go](https://github.com/JC01111/File-Sharing-System/blob/main/client/client.go) for my implementation, [client_test.go](https://github.com/JC01111/File-Sharing-System/blob/main/client_test/client_test.go) for some my own written test coverages, and [Design_Docs](https://github.com/JC01111/File-Sharing-System/blob/main/reference/Design_Docs.pdf) for my design documents.

Below topics I will introduce the functionality of my system and how do they work.

### Contents
- [Users And User Authentication]()
- [File Operations]()
- [Sharing and Revocation]()

## Functionality Overview
Here are 8 important functions:

- `InitUser`: Given a new username and password, create a new user.

- `GetUser`: Given a username and password, let the user log in if the password is correct.

- `User.StoreFile`: For a logged-in user, given a filename and file contents, create a new file or overwrite an existing file.

- `User.LoadFile`: For a logged-in user, given a filename, fetch the corresponding file contents.

- `User.AppendToFile`: For a logged-in user, given a filename and additional file contents, append the additional file contents at the end of the existing file contents, while following some efficiency requirements.

- `User.CreateInvitation`: For a logged-in user, given a filename and target user, generate an invitation UUID that the target user can use to gain access to the file.

- `User.AcceptInvitation`: For a logged-in user, given an invitation UUID, obtain access to a file shared by a different user. Allow the recipient user to access the file using a (possibly different) filename of their own choosing.

- `User.RevokeAccess`: For a logged-in user, given a filename and target user, revoke the target user’s access so that they are no longer able to access a shared file.

## Users And User Authentication
In this section, I designed two constructors to support creating new users and letting users log in to the system. And my implementation successfully solved the below questions.

#### Example
This example scenario illustrates how to create new users and let existing users log in.

- EvanBot calls `InitUser("evanbot", "password123")`.
  - This creates a new user with username "evanbot" and password "password123". If the username "evanbot" already exists, the function would return an error.
  - This constructor function creates and returns a User object with instance variables. EvanBot can call the instance methods of this object to perform file operations.
- There is no log out operation. If EvanBot is done running file operations, they can simply quit the program, which will destroy the User object (and its instance variables). This should not cause any data to be lost.
- Later, EvanBot runs your code again and calls `GetUser("evanbot", "password123")`.
  - This constructor function should create and return a User object corresponding to the existing EvanBot user. As before, the object can have instance variables, and EvanBot can call the instance methods to perform file operations.
  - If the password is incorrect, the function would return an error.
- CodaBot calls `InitUser("codabot", "password123")`.
  - The function should create and return a User object corresponding to the new CodaBot user.
  - Note that different users could choose the same password.


### Design Requirements: Usernames and Passwords
___

#### Usernames:
- Each user has a unique username.
- Usernames are case-sensitive: `Bob` and `bob` are different users.
- Usernames can be any string with 1 or more characters (not necessarily alphanumeric).

#### Passwords:
- Different users might choose to use the same password.
- The passwords provided by users have sufficient entropy for the PBKDF slow hash function to output an unpredictable string that an attacker cannot guess by brute force.
- The passwords provided by users do not have sufficient entropy to resist brute-force attacks on any of the other fast hash functions (Hash, HashKDF, or HMAC).
- Passwords can be any string with 0 or more characters (not necessarily alphanumeric, and could be the empty string).

### Design Requirements: Multiple Devices
___

Users must be able to create multiple User instances on different devices. In other words, a user should be able to call `GetUser` multiple times, with the same username and password, to obtain multiple different copies of the `User` struct on multiple different devices.

All changes to files made from one device must be reflected on all other devices immediately (i.e. a user should not have to call `GetUser` again to see the changes).

**Example** <br>
This example scenario illustrates how users should be able to create multiple User instances on multiple devices:

- EvanBot has a copy of the system’s code running on their laptop. EvanBot has another, duplicate copy of the system’s code running on their phone.
- On the laptop, EvanBot calls `GetUser("evanbot", "password")`.
  - The system creates a User object in the laptop’s local memory. We’ll denote this object as `evanbot-laptop`.
- Without terminating the code running on the laptop, EvanBot calls `GetUser("evanbot", "password")` on their phone.
  - The system creates another User object in the phone’s local memory. We’ll denote this object as `evanbot-phone`.
  - `evanbot-laptop` and `evanbot-phone` are two different User structs. They exist on two different devices, and they both correspond to the same user (EvanBot).
- On the laptop, EvanBot calls `evanbot-laptop.StoreFile("toppings.txt", "syrup")`.
- On the phone, EvanBot calls `evanbot-phone.LoadFile("toppings.txt")` and sees “syrup”.
  - Note that duplicate user objects, running on separate devices, should be able to see the latest updates to files.
- On the phone, EvanBot calls `evanbot-phone.AppendToFile("toppings.txt", "and butter")`.
- On the laptop, EvanBot calls `evanbot-laptop.LoadFile("toppings.txt")` and sees “syrup and butter”.
  - It would be incorrect behavior if the system returned “syrup”, because this means the append from the other device was not properly synced.

## File Operations
In this section, I designed three instance methods to support creating new files or overwriting the contents of existing files, reading file contents, and appending content to the end of existing files.

### Design Requirements: Namespacing
___
Note that different users can have files with the same name. A user’s namespace is defined as all of the filenames they are using. One user’s namespace could contain a filename that another user is also using. In that other user’s namespace, that same filename could refer to a different file (or the same file, if it was shared).

**Example:** <br>
This example scenario illustrates how file storage and namespacing works:

- EvanBot calls `StoreFile("foods.txt", "pancakes")`.
  - Assuming that EvanBot has never stored to foods.txt before, this creates a new file called foods.txt in EvanBot’s personal namespace.
- EvanBot calls `LoadFile("foods.txt")` and sees “pancakes”.
- EvanBot calls `StoreFile("foods.txt", "cookies")`.
    - Because foods.txt is an existing file, this call should overwrite the entire file with the new contents.
- EvanBot calls `LoadFile("foods.txt")` and sees “cookies”.
- EvanBot calls `LoadFile("drinks.txt")` and sees an error, because there is no file named drinks.txt in EvanBot’s personal namespace.
- EvanBot calls `AppendToFile("foods.txt", "and pancakes")`.
    - Instead of overwriting the entire file, this should append additional contents to the end of an existing file.
- EvanBot calls `LoadFile("foods.txt")` and sees “cookies and pancakes”.
- EvanBot calls `AppendToFile("foods.txt", "and hash browns")`.
- EvanBot calls `LoadFile("foods.txt")` and sees “cookies and pancakes and hash browns”.
- EvanBot calls `StoreFile("foods.txt", "pancakes")`.
    - This overwrites the entire file (including appends) with the new contents.
- EvanBot calls `LoadFile("foods.txt")` and sees “pancakes”.
- EvanBot calls `AppendToFile("drinks.txt", "and cookies")` and sees an error, because there is no file named drinks.txt in EvanBot’s personal namespace.
- CodaBot calls `StoreFile("foods.txt", "waffles")`.
    - Note that this creates a new file in CodaBot’s personal namespace named foods.txt. This should not interfere with the foods.txt file in EvanBot’s namespace, which is a different file.
- CodaBot calls `LoadFile("foods.txt")` and sees “waffles”.
- EvanBot calls `LoadFile("foods.txt")` and sees “pancakes”.

### Design Requirements: Files
___

**Confidentiality of data:**
- You must ensure that no information is leaked about these 3 pieces of data:
  - File contents for all files.
  - Filenames for all files.
  - The length of the filenames for all files.
- You must also ensure that no information is leaked that could be directly or indirectly used to learn these 3 pieces of data.
  - For example, if you have a secret key that you’re using to encrypt some file contents, you’ll need to ensure that secret key is not leaked either.
- You may leak information about any other values besides the ones listed above.
  - For example: It’s okay if an adversary learns usernames, length of a file, how many files a user has, etc.

**Integrity of data:**
- You must be able to detect when an attacker has tampered with the contents of a file.

**Filenames:**
- Filenames can be any string with 0 or more characters (not necessarily alphanumeric, and could be an empty string).
- Different users can have files with the same filename, but they could refer to different files.

### Design Requirements: Bandwidth & Append Efficiency
___
All functions except for `AppendToFile` have no efficiency requirements.

The efficiency requirement for appending is measured in terms of bandwidth, _not_ in terms of time complexity or space complexity. This means that your append can use unlimited amounts of local compute (e.g. you can encrypt and decrypt as much data as you’d like).

Recall that DataStore and KeyStore are remote databases. This means that when you call `DataStoreGet`, you are downloading all data at the specified UUID from DataStore to the local device running your code. Similarly, when you call `DataStoreSet`, you are uploading all the specified data from your local device running your code to DataStore. The only efficiency requirement for `AppendToFile` is that the total amount of data uploaded with calls to `DataStoreSet` and downloaded with calls to `DataStoreGet` must be efficient.

The bandwidth used by a call to `AppendToFile` is defined as the total size of all data in calls to `DataStoreSet` and `DataStoreGet`. All calls that are _not_ `DataStoreSet` or `DataStoreGet` do not affect the total bandwidth.

The total bandwidth should only scale with the size of the append (i.e. the number of bytes in the `content` argument to `AppendToFile`). In other words, if you are appending n bytes to the file, it’s okay (and unavoidable) that you’ll need to upload at least n bytes of data to the Datastore.

The total append bandwidth can additionally include some small constant factor. An example of a reasonable constant would be 256 bytes on every call to append.

The total bandwidth should not scale with (including but not limited to):

- Total file size
- Number of files
- Length of the filename
- Number of appends
- Size of previous append
- Length of username
- Length of password
- Number of users the file is shared with

**Example:** <br>
Here is one way to consider whether your design scales with the number of appends. Suppose we call `AppendToFile` on a file 10,000 times, appending 1 byte every time. The 1,000th and 10,000th call to `AppendToFile` should use the same total bandwidth as the 1st append operation.

Here is one way to consider whether your design scales with the size of the previous append. Suppose we call `AppendToFile` to append 1 terabyte of data to a file. Then, we call `AppendToFile` again on the same file to append another 100 bytes. The total bandwidth of the second call to append should not include the 1 terabyte of bandwidth from the previous (first) append.

In general, one way to check for efficiency is to imagine a graph where the x-axis is the potential scaling factor (e.g. file size), and the y-axis is the total bandwidth. The plot of scaling factor vs. total bandwidth should be a flat line, not an upwards sloping line.

**Example:** <br>
As an analogy, imagine that the users of this system have a limited phone data plan. We want to avoid excessive charges to their data plan, so we want to avoid downloading or uploading unnecessary data when appending.

For example, a naive implementation would involve:

1. The user calls `DataStoreGet` to download the entire contents of the file.
2. The user decrypts the file locally.
3. The user appends the contents locally.
4. The user encrypts the entire file contents.
5. The user calls `DataStoreSet` to upload the entire file to DataStore.

Note for steps 2 & 4: These parts do not count against bandwidth efficiency. Recall, only `DataStoreGet` and `DataStoreSet` count for bandwidth calculation, and local computations do not count against efficiency requirements.

This implementation is inefficient because in step 1, the call to `DataStoreGet` downloads the entire file. This implementation is additionally inefficient due to step 5, where we call `DataStoreSet` and upload the entire file contents.

For example, if we had a 10 terabyte file, and we wanted to append 100 bytes to the file, the implementation above would have a total bandwidth of 20 terabytes + 100 bytes. An efficient implementation would use 100 bytes of bandwidth (possibly plus some constant).



## Sharing and Revocation
In this section, I designed three instance methods to support sharing files with other users and revoking file access from other users.

**Example** <br>
This example scenario illustrates how file sharing occurs.

- EvanBot calls `StoreFile("foods.txt", "eggs")`.
  - Assuming that foods.txt did not previously exist in EvanBot’s file namespace, this creates a new file named foods.txt in EvanBot’s namespace.
  - Because EvanBot created the new file with a call to `StoreFile`, EvanBot is the owner of this file.

- EvanBot calls `CreateInvitation("foods.txt", "codabot")`.
  - This function returns a UUID, which we’ll call an invitation Datastore pointer.
  - The invitation UUID can be any UUID you like. For example, you could collect/compute any values that you want to send to the recipient user for them to access the file. Then, you could securely store these values on Datastore at some UUID, and return that UUID.
- EvanBot uses a secure communication channel (outside of your system) to deliver the invitation UUID to CodaBot. Using this secure channel, CodaBot receives the identity of the sender (EvanBot) and the invitation UUID generated by EvanBot.

- CodaBot calls `AcceptInvitation("evanbot", invitationPtr, "snacks.txt")`.
  - CodaBot passes in the identity of the sender and the invitation UUID generated by EvanBot.
  - CodaBot also passes in a filename (snacks.txt here). Note that CodaBot (the recipient user) can choose to give the file a different name while accepting the invitation.

- CodaBot calls `LoadFile("snacks.txt")` and sees “eggs”.
  - Note that CodaBot refers to the file using the name they specified when they accepted the invitation.

- EvanBot calls `LoadFile("foods.txt")` and sees “eggs”.
  - Note that different users can refer to the same file using different filenames.

- EvanBot calls `AppendToFile("foods.txt", "and bacon")`.
- CodaBot calls `LoadFile("snacks.txt")` and sees “eggs and bacon”.
  - Note that all users should be able to see modifications to the file.

### Design Requirements: Sharing and Revoking
___
File access

- The owner of a file is the user who initially created the file (i.e. with the first call to `StoreFile`).
- The owner must always be able to access the file. All users who have accepted an invitation to access the file (and who have not been revoked) must also be able to access the file. These users must be able to:
  - Read the file contents with `LoadFile`.
  - Overwrite the file contents with `StoreFile`.
  - Append to the file with `AppendToFile`.
  - Share the file with `CreateInvitation`.
- If a user changes the file contents, all users with access must immediately see the changes. The next time they try to access the file, all users with access should see the latest version.
- All users should be reading and modifying the same copy of the file. You may not create copies of the file.

### Design Requirements: Revoked User Adversary
___
Once a user has their access revoked, they become a malicious user, who we’ll call the Revoked User Adversary. The Revoked User Adversary will not collude with any other users, and they will not collude with the Datastore Adversary.

The Revoked User Adversary’s goal is to re-obtain access to the file. The revoked user will not perform malicious actions on other files that they still have access to. Their only goal is to re-obtain access to the file that they lost access to.

The Revoked User Adversary might attempt to re-obtain access by calling functions with different arguments (e.g. calling `AcceptInvitation` again).

The Revoked User Adversary may also try to re-obtain access by calling `DatastoreGet` and `DatastoreSet` and maliciously affecting Datastore. However, unlike the Datastore Adversary, they do not have a global view of Datastore (i.e. they cannot list all UUIDs that have been in use).

Prior to having their access revoked, the Revoked User Adversary could have written down any values that they have previously seen. The Revoked User Adversary has a copy of your code running on their local computer, so they could inspect the code and learn the values of any variables that you computed.

Your code should ensure that the Revoked User Adversary is unable to learn anything about any future writes or appends to the file (learning about the file before they got revoked is okay). For example, they cannot know what the latest contents of the file are, and they should be unable to make modifications to the file without being detected. Also, they cannot know when future updates are happening (e.g. they should not be able to deduce how many times the file has been updated in the past day).