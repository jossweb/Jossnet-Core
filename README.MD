## Compilation:
- Server :
  gcc server.c endpoint.c common.c ../keygen/keygen.c ../cjson/cJSON.c\
  -I../build/include \
  ../build/lib/libnoisekeys.a \
  ../build/lib/libnoiseprotobufs.a \
  ../build/lib/libnoiseprotocol.a \
  -o server
- Client : gcc client.c ../server/common.c \
  -I../build/include \
  ../build/lib/libnoisekeys.a \
  ../build/lib/libnoiseprotobufs.a \
  ../build/lib/libnoiseprotocol.a \
  -o client



sudo apt-get install libcjson-dev

./client Noise_NN_25519_AESGCM_SHA256 localhost 2006
