#pragma once

int file_system();
int file_encrypt(RSAPublicKey* RSApubKey);
int file_decrypt(RSAPrvateKey* RSAprvKey);
void spn_init_session(MainKey sessionKey, spn_Text * initVect);