#include "Types.h"
#include "Utilities.h"

#include <zlib/zlib.h>
#include <zstd/zstd.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

namespace PeepoHappy
{
	namespace ZLIB
	{
		inline auto DllHandle = ::LoadLibraryW(PeepoHappy::UTF8::WideArg("zlib.dll").c_str());
		inline auto InflateInit2_ = reinterpret_cast<int(*)(z_streamp strm, int windowBits, const char *version, int stream_size)>(::GetProcAddress(DllHandle, "inflateInit2_"));
		inline auto Inflate = reinterpret_cast<int(*)(z_streamp strm, int flush)>(::GetProcAddress(DllHandle, "inflate"));
		inline auto InflateEnd = reinterpret_cast<int(*)(z_streamp strm)>(::GetProcAddress(DllHandle, "inflateEnd"));
		// NOTE: No need to ::FreeLibrary(DllHandle); for static lifetime
	}

	namespace ZSTD
	{
		inline auto DllHandle = ::LoadLibraryW(PeepoHappy::UTF8::WideArg("libzstd.dll").c_str());
		inline auto GetFrameContentSize = reinterpret_cast<unsigned long long(*)(const void *src, size_t srcSize)>(::GetProcAddress(DllHandle, "ZSTD_getFrameContentSize"));
		inline auto Decompress = reinterpret_cast<size_t(*)(void* dst, size_t dstCapacity, const void* src, size_t compressedSize)>(::GetProcAddress(DllHandle, "ZSTD_decompress"));
		inline auto IsError = reinterpret_cast<unsigned(*)(size_t code)>(::GetProcAddress(DllHandle, "ZSTD_decompress"));
		// NOTE: No need to ::FreeLibrary(DllHandle); for static lifetime
	}

	namespace Compression
	{
		enum class Method
		{
			None,
			GZip,
			ZStd,
		};

#pragma pack(push, 1)
		struct GZipHeader
		{
			u8 Magic[2];
			u8 CompressionMethod;
			u8 Flags;
			u32 Timestamp;
			u8 ExtraFlags;
			u8 OperatingSystem;
		};
#pragma pack(pop)

		static_assert(sizeof(GZipHeader) == 10);

		inline bool HasValidGZipHeader(const u8* fileContent, size_t fileSize)
		{
			if (fileSize <= sizeof(GZipHeader))
				return false;

			const GZipHeader* header = reinterpret_cast<const GZipHeader*>(fileContent);
			return (header->Magic[0] == 0x1F && header->Magic[1] == 0x8B) && (header->CompressionMethod == Z_DEFLATED);
		}

		inline bool Decompress(Method method, const u8* inCompressedData, size_t inDataSize, u8* outDecompressedData, size_t outDataSize)
		{
			switch (method)
			{
			case Method::None:
			{
				if (outDataSize < inDataSize)
					return false;

				std::memmove(outDecompressedData, inCompressedData, inDataSize);
				return true;
			}

			case Method::GZip:
			{
				z_stream zStream = {};
				zStream.zalloc = Z_NULL;
				zStream.zfree = Z_NULL;
				zStream.opaque = Z_NULL;
				zStream.avail_in = static_cast<uInt>(inDataSize);
				zStream.next_in = const_cast<Bytef*>(inCompressedData);
				zStream.avail_out = static_cast<uInt>(outDataSize);
				zStream.next_out = static_cast<Bytef*>(outDecompressedData);

				const int initResult = ZLIB::InflateInit2_(&zStream, 31, ZLIB_VERSION, static_cast<int>(sizeof(z_stream)));
				if (initResult != Z_OK)
					return false;

				const int inflateResult = ZLIB::Inflate(&zStream, Z_FINISH);

				const int endResult = ZLIB::InflateEnd(&zStream);
				if (endResult != Z_OK)
					return false;

				return true;
			}

			case Method::ZStd:
			{
				const size_t decompressResult = ZSTD::Decompress(outDecompressedData, outDataSize, inCompressedData, inDataSize);

				return true;
			}

			default:
				assert(false);
				return false;
			}
		}
	}

}

namespace FArcExtractor
{
	namespace
	{
		inline u16 ByteSwapU16(u16 value) { return _byteswap_ushort(value); }
		inline u32 ByteSwapU32(u32 value) { return _byteswap_ulong(value); }
		inline u64 ByteSwapU64(u64 value) { return _byteswap_uint64(value); }
	}

	enum class FArcSignature
	{
		Invalid = 0,
		FArC = 1,
		FARC = 2,
		FARc = 3,
	};

	struct FArcFlags
	{
		u32 Unk0 : 1;
		u32 GZipCompressed : 1;
		u32 Encrypted : 1;
		u32 Unk3 : 1;
		u32 Unk4 : 1;
		u32 Unk5 : 1;
		u32 ZStdCompressed : 1;
		u32 Unk7 : 1;
	};

	struct FArcFileFlags
	{
		u32 Unk0 : 1;
		u32 GZipCompressed : 1;
		u32 Encrypted : 1;
		u32 Unk3 : 1;
		u32 SplitChunks : 1;
		u32 ZStdCompressed : 1;
	};

	struct FArcFileEntry
	{
		std::string_view FileName;
		u32 Offset;
		u32 CompressedSize;
		u32 UncompressedSize;
		FArcFileFlags Flags;

		std::unique_ptr<u8[]> DecompressedFileContent;
	};

	struct FArc
	{
		std::unique_ptr<u8[]> FileContent;
		size_t FileSize;

		FArcSignature Signature;
		FArcFlags Flags;
		std::vector<FArcFileEntry> Entries;
	};

	static_assert(sizeof(FArcFileFlags) == sizeof(u32));
	static_assert(sizeof(FArcFlags) == sizeof(u32));

	FArc OpenReadDecryptAndParseFArcEntries(std::string_view inputFArcPath)
	{
		FArc outFArc = {};

		auto[fileContent, fileSize] = PeepoHappy::IO::ReadEntireFile(inputFArcPath);
		outFArc.FileContent = std::move(fileContent);
		outFArc.FileSize = fileSize;

		const u8* readHead = outFArc.FileContent.get();
		const u32 signature = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);

		outFArc.Signature = (signature == 'FArC') ? FArcSignature::FArC : (signature == 'FARC') ? FArcSignature::FARC : (signature == 'FARc') ? FArcSignature::FARc : FArcSignature::Invalid;
		if (outFArc.Signature == FArcSignature::Invalid)
		{
			fprintf(stderr, "[ERROR] Unexpected FArc signature!\n");
		}
		else
		{
			const u32 headerSize = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);
			const u32 farcFlags = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);
			const u32 unkAlways0 = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);

			outFArc.Flags = *reinterpret_cast<const FArcFlags*>(&farcFlags);
			if (outFArc.Flags.Encrypted)
			{
				const auto key = PeepoHappy::Crypto::ParseAes128KeyHexByteString("62EC7CD79141695E53592ACC10CDC04C");
				constexpr size_t encryptedDataOffset = 16 /* unencrypted start of header */ + PeepoHappy::Crypto::Aes128IVSize;

				PeepoHappy::Crypto::Aes128IVBytes iv = {};
				memcpy(iv.data(), outFArc.FileContent.get() + sizeof(iv), sizeof(iv));

				PeepoHappy::Crypto::DecryptAes128Cbc(outFArc.FileContent.get() + encryptedDataOffset, outFArc.FileContent.get() + encryptedDataOffset, outFArc.FileSize - encryptedDataOffset, key, iv);
				readHead = outFArc.FileContent.get() + encryptedDataOffset;
			}

			const u32 maybeAlignmentA = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);
			const u32 unkEither1Or4 = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);
			const u32 fileCount = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);
			const u32 maybeAlignmentB = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);

			outFArc.Entries.reserve(fileCount);
			for (size_t i = 0; i < fileCount; i++)
			{
				auto& entry = outFArc.Entries.emplace_back();
				entry.FileName = std::string_view(reinterpret_cast<const char*>(readHead)); readHead += entry.FileName.size() + sizeof('\0');
				entry.Offset = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);
				entry.CompressedSize = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);
				entry.UncompressedSize = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);
				const u32 fileFlags = ByteSwapU32(*reinterpret_cast<const u32*>(readHead)); readHead += sizeof(u32);
				entry.Flags = *reinterpret_cast<const FArcFileFlags*>(&fileFlags);

				if (outFArc.Flags.Encrypted)
					entry.Offset += static_cast<u32>(PeepoHappy::Crypto::Aes128KeySize);
			}
		}

		return outFArc;
	}

	bool ReadAndDecompressAllFArcEntries(FArc& inOutFArc)
	{
		if (inOutFArc.FileContent == nullptr || inOutFArc.FileSize < 16)
			return false;

		for (auto& entry : inOutFArc.Entries)
		{
			entry.DecompressedFileContent = std::make_unique<u8[]>(entry.UncompressedSize);
			const u8* readHead = (inOutFArc.FileContent.get() + entry.Offset);

			if (entry.Flags.SplitChunks)
			{
				const u32 strangeUnkownData = *reinterpret_cast<const u32*>(readHead); readHead += sizeof(u32);
				u32 remainingCompressedSize = (entry.CompressedSize - static_cast<u32>(sizeof(strangeUnkownData)));

				for (size_t safetyLimit = 0; safetyLimit < 0x4000; safetyLimit++)
				{
					const u32 chunkSize = *reinterpret_cast<const u32*>(readHead); readHead += sizeof(u32);

					remainingCompressedSize -= (chunkSize + sizeof(chunkSize));
					if (remainingCompressedSize <= sizeof(u32))
						break;
				}
			}

			const u32 currentFilePosition = static_cast<u32>(std::distance<const u8*>(inOutFArc.FileContent.get(), readHead));
			const auto compressedSizeWithoutChunkTable = entry.CompressedSize - (currentFilePosition - entry.Offset);

			if (entry.Flags.GZipCompressed)
			{
				const bool wasSuccessful = PeepoHappy::Compression::Decompress(PeepoHappy::Compression::Method::GZip,
					readHead, entry.CompressedSize, entry.DecompressedFileContent.get(), entry.UncompressedSize);
			}
			else if (entry.Flags.ZStdCompressed)
			{
				const size_t decompressResult = PeepoHappy::Compression::Decompress(PeepoHappy::Compression::Method::ZStd,
					readHead, entry.CompressedSize, entry.DecompressedFileContent.get(), entry.UncompressedSize);
			}
			else
			{
				std::memcpy(entry.DecompressedFileContent.get(), readHead, entry.UncompressedSize);
			}
		}

		return true;
	}

	bool ExtractWriteAllFArcEntriesIntoDirectory(const FArc& inFArc, std::string_view outputDirectory)
	{
		if (inFArc.FileContent == nullptr || inFArc.Signature == FArcSignature::Invalid)
			return false;

		PeepoHappy::IO::CreateFileDirectory(outputDirectory);

		char outputPathBuffer[2048] = {};
		::memcpy(outputPathBuffer, outputDirectory.data(), outputDirectory.size());
		outputPathBuffer[outputDirectory.size()] = '/';

		char* pathBufferFileName = &outputPathBuffer[outputDirectory.size() + 1];

		for (const auto& entry : inFArc.Entries)
		{
			if (entry.FileName.empty() || entry.DecompressedFileContent == nullptr)
			{
				fprintf(stderr, "[ERROR] Unable to extract file[%zu]\n", static_cast<size_t>(std::distance(&inFArc.Entries.front(), &entry)));
				continue;
			}

			::memcpy(pathBufferFileName, entry.FileName.data(), entry.FileName.size() + 1);
			PeepoHappy::IO::WriteEntireFile(outputPathBuffer, entry.DecompressedFileContent.get(), entry.UncompressedSize);
		}

		return true;
	}

	int EntryPoint()
	{
		const auto[argc, argv] = PeepoHappy::UTF8::GetCommandLineArguments();

		if (argc < 2)
		{
			printf("Description:\n");
			printf("    A program to extract compressed/encrypted files stored within modern FArc files\n");
			printf("    used by Fate Grand Order Arcade\n");
			printf("\n");
			printf("Usage:\n");
			printf("    FgoFArcExtractor.exe \"{input_farc_file}.farc\"\n");
			printf("\n");
			printf("Notes:\n");
			printf("    Output files are written into a same directory sub directory named after the input FArc file.\n");
			printf("\n");
			printf("Credits:\n");
			printf("    Programmed and reverse engineered by samyuu\n");
			printf("    Special thanks to Skyth and everybody else involved in the research\n");
			printf("    of other FArc format versions used by different games\n");
			printf("    which have indirectly influenced my decision making for this one <3\n");
			printf("\n");
			return EXIT_WIDEPEEPOSAD;
		}

		const auto inputFArcPath = std::string_view(argv[1]);
		const auto outputDirectory = PeepoHappy::Path::TrimFileExtension(inputFArcPath);

		auto farc = OpenReadDecryptAndParseFArcEntries(inputFArcPath);
		if (!ReadAndDecompressAllFArcEntries(farc))
		{
			fprintf(stderr, "[ERROR] Failed to parse file entries\n");
			return EXIT_WIDEPEEPOSAD;
		}

		if (!ExtractWriteAllFArcEntriesIntoDirectory(farc, outputDirectory))
		{
			fprintf(stderr, "[ERROR] Failed to extract output files\n");
			return EXIT_WIDEPEEPOSAD;
		}

		return EXIT_WIDEPEEPOHAPPY;
	}
}

int main()
{
	return FArcExtractor::EntryPoint();
}
