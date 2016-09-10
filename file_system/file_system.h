#pragma once

#define FILE_OPEN_ERROR 1

int file_system();
int file_encrypt(RSAPublicKey* RSApubKey);
int file_decrypt(RSAPrvateKey* RSAprvKey);
void file_init_session(MainKey sessionKey, spn_Text * initVect);