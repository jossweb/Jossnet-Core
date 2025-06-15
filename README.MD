![Jossnet banner](https://jossweb.fr/img/jossnet-banner.png)

## About Jossnet

This project aims to demonstrate the implementation of a secure and high-performance exchange system between a client and a server, relying on the Noise cryptographic protocol. The objective is to offer a modern, fast, and easily integrable architecture, while ensuring authentication and key management adapted to the needs of distributed applications.

Designed as a proof of concept, this project provides a solid foundation for exploring best practices in securing communications, automating onboarding, and protecting exchanges in various environments. It is intended for developers, students, and cybersecurity enthusiasts who wish to discover or experiment with innovative solutions for authentication and key management in client-server applications.

**Warning:** This project is still under development.

---

## Compilation

#### Compile server
```sh
gcc server.c endpoint.c ../common/common.c ../keygen/keygen.c ../cjson/cJSON.c \
  -I../build/include \
  ../build/lib/libnoisekeys.a \
  ../build/lib/libnoiseprotobufs.a \
  ../build/lib/libnoiseprotocol.a \
  -o server
```

#### Compile client
```sh
gcc client.c ../common/common.c ../keygen/keygen.c  ../cjson/cJSON.c \
  -I../build/include \
  ../build/lib/libnoisekeys.a \
  ../build/lib/libnoiseprotobufs.a \
  ../build/lib/libnoiseprotocol.a \
  -o client
```

---

## Dependencies

- [Noise-c](https://github.com/rweather/noise-c)
- [cJSON](https://github.com/DaveGamble/cJSON)

---

## Credits

This project uses code derived from [noise-c](https://github.com/rweather/noise-c),  
© 2016 Southern Storm Software, Pty Ltd., licensed under the MIT License.

---

## License

This project is licensed under the MIT License.  
See [LICENSE](./LICENSE) for more information.