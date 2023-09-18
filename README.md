# Multiparty-Chatroom
## Background
This is a coursework of HKUST COMP4621. It is a server-client application that allows real-time messaging between users. The server in this application serves as a moderator, which can handle messages from different clients concurrently without blocking I/O. Clients in this application are the end users who can send and receive messages from each other. They are expected to send messages asynchronously with the capability of receiving messages in real time, therefore multi-threading is enabled to ensure the sending and receiving functions can operate at the same time.

## Future Plan
Currently, the code base is a bit messy, which I plan to refactor it and re-implement it with C++ in the future. As a part of my C++ self-study plan, I'd revisit this project again after reading some books:
- Effective C++ 3rd Edition: For applying good C++ programming practices.
- Book related to network programming/ linux
- C++ STL related: Depends on time
