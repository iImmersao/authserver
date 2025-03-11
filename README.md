# authserver

A basic Spring Boot OAuth2 Authorization Server based on the code created in Sergey Kargopolov's Udemy course:

https://www.udemy.com/course/oauth2-in-spring-boot-applications

Significant changes are:
- The server now uses configuration for set-up and can handle multiple clients, rather than being hard-coded
- A simple MongoDB database is used to store the user name and password details, rather than having them hard-coded

There is a lot of debug output that would not be desirable in a real-world application, as it reveals information that should not be disclosed. This is merely present in order to help understanding of how the configuration is handled.

The MongoDB is extremely simple and the passwords are held in plain text. For a real-world application, this would be undesirable and so would need changing to use encrypted data.

The server is not based on the latest Spring Boot code and will need updating.
