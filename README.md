# ECC

A project which implements the Elliptic Curve Cryptography for the Diffie-Hellman keys exchange inside an Android device.

# How does it work?
The architecture is conceptually divided into two parts:
* a Client: it sends the messages that are automatically encrypted with the common pre-shared key.
* a Server which receives the messages encrypted, it decrypts them through the same shared key and it displays them on the screen.

## Implementation
### Hardware
At the hardware level, the connection is implemented through sockets and threads, one for each part.

# Goal of this project
The Goal of this project is to realise a message exchange system able to take into account the advantages of the Elliptic Curve cryptography which can be a great replacement of the well known RSA one, expecially in the IoT area.

# Contact
Linkedin:
 * [Jacopo Maria Valtorta](https://www.linkedin.com/in/jacopo-maria-valtorta)
 
[To be upload...]

SlideShare: [ECC]()
