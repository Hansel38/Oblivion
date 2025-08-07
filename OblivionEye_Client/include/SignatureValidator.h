#pragma once
#include <string>
#include <vector>  // TAMBAHKAN INI

// Deklarasi fungsi
bool ValidateFileSignature(const std::string& filePath);
bool ValidateExecutableSignature();
void ContinuousSignatureValidation();