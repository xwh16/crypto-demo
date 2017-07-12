#pragma once

#define FILE_OPEN_ERROR 1

int file_system();
int file_encrypt(RSAPublicKey* RSApubKey);
int file_decrypt(RSAPrivateKey* RSAprvKey);
void file_init_session(MainKey sessionKey, spn_Text * initVect);
void file_destroy_session(MainKey sessionKey, spn_Text *initVect);