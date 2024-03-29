#include "Utilities.h"

#define NOMINMAX
#include <Windows.h>
#include <bcrypt.h>

#ifndef  NT_SUCCESS
#define NT_SUCCESS(Status) (((::NTSTATUS)(Status)) >= 0)
#endif // ! NT_SUCCESS

#pragma comment(lib, "bcrypt.lib")

namespace PeepoHappy
{
	namespace UTF8
	{
		std::string Narrow(std::wstring_view inputString)
		{
			std::string utf8String;
			const int utf8Length = ::WideCharToMultiByte(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size() + 1), nullptr, 0, nullptr, nullptr) - 1;

			if (utf8Length > 0)
			{
				utf8String.resize(utf8Length);
				::WideCharToMultiByte(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size()), utf8String.data(), utf8Length, nullptr, nullptr);
			}

			return utf8String;
		}

		std::wstring Widen(std::string_view inputString)
		{
			std::wstring utf16String;
			const int utf16Length = ::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size() + 1), nullptr, 0) - 1;

			if (utf16Length > 0)
			{
				utf16String.resize(utf16Length);
				::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size()), utf16String.data(), utf16Length);
			}

			return utf16String;
		}

		bool AppearsToUse8BitCodeUnits(std::string_view uncertainUTF8Text)
		{
			size_t nullCount = 0;
			for (const char c : uncertainUTF8Text)
				nullCount += (c == '\0');

			if (uncertainUTF8Text.empty() || nullCount == 0)
				return true;

			const bool unusualNullCount = nullCount >= (uncertainUTF8Text.size() / 4);
			return !unusualNullCount;
		}

		std::pair<int, const char**> GetCommandLineArguments()
		{
			static std::vector<std::string> argvString;
			static std::vector<const char*> argvCStr;

			if (!argvString.empty() || !argvCStr.empty())
				return { static_cast<int>(argvString.size()), argvCStr.data() };

			int argc = 0;
			auto argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);

			argvString.reserve(argc);
			argvCStr.reserve(argc);

			for (auto i = 0; i < argc; i++)
				argvCStr.emplace_back(argvString.emplace_back(UTF8::Narrow(argv[i])).c_str());

			::LocalFree(argv);
			return { argc, argvCStr.data() };
		}

		std::string GetExecutableFilePath()
		{
			wchar_t fileNameBuffer[MAX_PATH];
			const auto moduleFileName = std::wstring_view(fileNameBuffer, ::GetModuleFileNameW(NULL, fileNameBuffer, MAX_PATH));

			return (moduleFileName.size() < MAX_PATH) ? UTF8::Narrow(moduleFileName) : "";
		}

		std::string GetExecutableDirectory()
		{
			return std::string(Path::GetDirectoryName(GetExecutableFilePath()));
		}

		WideArg::WideArg(std::string_view inputString)
		{
			// NOTE: Length **without** null terminator
			convertedLength = ::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size() + 1), nullptr, 0) - 1;

			if (convertedLength <= 0)
			{
				stackBuffer[0] = L'\0';
				return;
			}

			if (convertedLength < stackBuffer.size())
			{
				::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size()), stackBuffer.data(), convertedLength);
				stackBuffer[convertedLength] = L'\0';
			}
			else
			{
				heapBuffer = std::make_unique<wchar_t[]>(convertedLength + 1);
				::MultiByteToWideChar(CP_UTF8, 0, inputString.data(), static_cast<int>(inputString.size()), heapBuffer.get(), convertedLength);
				heapBuffer[convertedLength] = L'\0';
			}
		}

		const wchar_t* WideArg::c_str() const
		{
			return (convertedLength < stackBuffer.size()) ? stackBuffer.data() : heapBuffer.get();
		}
	}

	namespace Path
	{
		std::string_view GetFileExtension(std::string_view filePath)
		{
			const size_t lastSeparator = filePath.find_last_of("./\\");
			if (lastSeparator != std::string_view::npos)
			{
				if (filePath[lastSeparator] == '.')
					return filePath.substr(lastSeparator);
			}
			return std::string_view(filePath.data(), 0);
		}

		std::string_view GetFileName(std::string_view filePath, bool includeExtension)
		{
			const size_t lastSeparator = filePath.find_last_of("/\\");
			const auto fileName = (lastSeparator == std::string_view::npos) ? filePath : filePath.substr(lastSeparator + 1);
			return (includeExtension) ? fileName : TrimFileExtension(fileName);
		}

		std::string_view GetDirectoryName(std::string_view filePath)
		{
			const auto fileName = GetFileName(filePath);
			return fileName.empty() ? filePath : filePath.substr(0, filePath.size() - fileName.size() - 1);
		}

		std::string_view TrimFileExtension(std::string_view filePath)
		{
			return filePath.substr(0, filePath.size() - GetFileExtension(filePath).size());
		}

		bool HasFileExtension(std::string_view filePath, std::string_view extensionToCheckFor)
		{
			assert(!extensionToCheckFor.empty() && extensionToCheckFor[0] == '.');
			return ASCII::MatchesInsensitive(GetFileExtension(filePath), extensionToCheckFor);
		}
	}

	namespace IO
	{
		void CreateFileDirectory(std::string_view directoryPath)
		{
			::CreateDirectoryW(UTF8::WideArg(directoryPath).c_str(), 0);
		}

		std::pair<std::unique_ptr<u8[]>, size_t> ReadEntireFile(std::string_view filePath)
		{
			std::unique_ptr<u8[]> fileContent = nullptr;
			size_t fileSize = 0;

			::HANDLE fileHandle = ::CreateFileW(UTF8::WideArg(filePath).c_str(), GENERIC_READ, (FILE_SHARE_READ | FILE_SHARE_WRITE), NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (fileHandle != INVALID_HANDLE_VALUE)
			{
				::LARGE_INTEGER largeIntegerFileSize = {};
				::GetFileSizeEx(fileHandle, &largeIntegerFileSize);

				if (fileSize = static_cast<size_t>(largeIntegerFileSize.QuadPart); fileSize > 0)
				{
					if (fileContent = std::make_unique<u8[]>(fileSize); fileContent != nullptr)
					{
						assert(fileSize < std::numeric_limits<DWORD>::max() && "No way that's ever gonna happen, right?");

						DWORD bytesRead = 0;
						::ReadFile(fileHandle, fileContent.get(), static_cast<DWORD>(fileSize), &bytesRead, nullptr);
					}
				}

				::CloseHandle(fileHandle);
			}

			return { std::move(fileContent), fileSize };
		}

		bool WriteEntireFile(std::string_view filePath, const u8* fileContent, size_t fileSize)
		{
			if (filePath.empty() || fileContent == nullptr || fileSize == 0)
				return false;

			::HANDLE fileHandle = ::CreateFileW(UTF8::WideArg(filePath).c_str(), GENERIC_WRITE, (FILE_SHARE_READ | FILE_SHARE_WRITE), NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (fileHandle == INVALID_HANDLE_VALUE)
				return false;

			assert(fileSize < std::numeric_limits<DWORD>::max() && "No way that's ever gonna happen, right?");

			DWORD bytesWritten = 0;
			::WriteFile(fileHandle, fileContent, static_cast<DWORD>(fileSize), &bytesWritten, nullptr);

			::CloseHandle(fileHandle);
			return true;
		}
	}

	namespace Crypto
	{
		namespace Detail
		{
			enum class Operation { Decrypt, Encrypt };

			bool BCryptAes128Cbc(Operation operation, const u8* inData, size_t inDataSize, u8* outData, size_t outDataSize, u8* key, u8* iv)
			{
				bool successful = false;
				::NTSTATUS status = {};
				::BCRYPT_ALG_HANDLE algorithmHandle = {};

				status = ::BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_AES_ALGORITHM, nullptr, 0);
				if (NT_SUCCESS(status))
				{
					status = ::BCryptSetProperty(algorithmHandle, BCRYPT_CHAINING_MODE, reinterpret_cast<PBYTE>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)), sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
					if (NT_SUCCESS(status))
					{
						ULONG keyObjectSize = {};
						ULONG copiedDataSize = {};

						status = ::BCryptGetProperty(algorithmHandle, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PBYTE>(&keyObjectSize), sizeof(ULONG), &copiedDataSize, 0);
						if (NT_SUCCESS(status))
						{
							::BCRYPT_KEY_HANDLE symmetricKeyHandle = {};
							auto keyObject = std::make_unique<u8[]>(keyObjectSize);

							status = ::BCryptGenerateSymmetricKey(algorithmHandle, &symmetricKeyHandle, keyObject.get(), keyObjectSize, key, static_cast<ULONG>(Aes128KeySize), 0);
							if (NT_SUCCESS(status))
							{
								if (operation == Operation::Decrypt)
								{
									status = ::BCryptDecrypt(symmetricKeyHandle, const_cast<u8*>(inData), static_cast<ULONG>(inDataSize), nullptr, iv, static_cast<ULONG>(Aes128IVSize), outData, static_cast<ULONG>(outDataSize), &copiedDataSize, 0);
									if (NT_SUCCESS(status))
										successful = true;
									else
										fprintf(stderr, "BCryptDecrypt() failed with 0x%X\n", status);
								}
								else if (operation == Operation::Encrypt)
								{
									status = ::BCryptEncrypt(symmetricKeyHandle, const_cast<u8*>(inData), static_cast<ULONG>(inDataSize), nullptr, iv, static_cast<ULONG>(Aes128IVSize), outData, static_cast<ULONG>(outDataSize), &copiedDataSize, 0);
									if (NT_SUCCESS(status))
										successful = true;
									else
										fprintf(stderr, "BCryptEncrypt() failed with 0x%X\n", status);
								}
								else
								{
									assert(false);
								}

								if (symmetricKeyHandle)
									::BCryptDestroyKey(symmetricKeyHandle);
							}
							else
							{
								fprintf(stderr, "BCryptGenerateSymmetricKey() failed with 0x%X\n", status);
							}
						}
						else
						{
							fprintf(stderr, "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed with 0x%X\n", status);
						}
					}
					else
					{
						fprintf(stderr, "BCryptSetProperty(BCRYPT_CHAINING_MODE) failed with 0x%X\n", status);
					}

					if (algorithmHandle)
						::BCryptCloseAlgorithmProvider(algorithmHandle, 0);
				}
				else
				{
					fprintf(stderr, "BCryptOpenAlgorithmProvider(BCRYPT_AES_ALGORITHM) failed with 0x%X\n", status);
				}

				return successful;
			}
		}

		bool DecryptAes128Cbc(const u8* inEncryptedData, u8* outDecryptedData, size_t inOutDataSize, Aes128KeyBytes key, Aes128IVBytes iv)
		{
			return Detail::BCryptAes128Cbc(Detail::Operation::Decrypt, inEncryptedData, inOutDataSize, outDecryptedData, inOutDataSize, key.data(), iv.data());
		}

		bool EncryptAes128Cbc(const u8* inDecryptedData, u8* outEncryptedData, size_t inOutDataSize, Aes128KeyBytes key, Aes128IVBytes iv)
		{
			assert(Align(inOutDataSize, Aes128Alignment) == inOutDataSize);
			return Detail::BCryptAes128Cbc(Detail::Operation::Encrypt, inDecryptedData, inOutDataSize, outEncryptedData, inOutDataSize, key.data(), iv.data());
		}

		Aes128KeyBytes ParseAes128KeyHexByteString(std::string_view hexByteString)
		{
			constexpr size_t hexDigitsPerByte = 2;

			char upperCaseHexChars[(Aes128KeySize * hexDigitsPerByte) + sizeof('\0')] = {};
			size_t hexCharsWrittenSoFar = 0;

			for (size_t charIndex = 0; charIndex < hexByteString.size(); charIndex++)
			{
				if (ASCII::IsWhiteSpace(hexByteString[charIndex]))
					continue;

				const char upperCaseChar = ASCII::ToUpperCase(hexByteString[charIndex]);
				upperCaseHexChars[hexCharsWrittenSoFar++] = ((upperCaseChar >= '0' && upperCaseChar <= '9') || (upperCaseChar >= 'A' && upperCaseChar <= 'F')) ? upperCaseChar : '0';

				if (hexCharsWrittenSoFar >= std::size(upperCaseHexChars))
					break;
			}

			Aes128KeyBytes resultKeyBytes = {};
			for (size_t byteIndex = 0; byteIndex < resultKeyBytes.size(); byteIndex++)
			{
				auto upperCaseHexCharToNibble = [](char c) -> u8 { return (c >= '0' && c <= '9') ? (c - '0') : (c >= 'A' && c <= 'F') ? (0xA + (c - 'A')) : 0x0; };

				u8 combinedByte = 0x00;
				combinedByte |= (upperCaseHexCharToNibble(upperCaseHexChars[(byteIndex * hexDigitsPerByte) + 0]) << 4);
				combinedByte |= (upperCaseHexCharToNibble(upperCaseHexChars[(byteIndex * hexDigitsPerByte) + 1]) << 0);
				resultKeyBytes[byteIndex] = combinedByte;
			}
			return resultKeyBytes;
		}
	}
}
