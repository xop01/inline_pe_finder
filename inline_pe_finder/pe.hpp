#pragma once

#include <Windows.h>
#include <fstream>
#include <string>
#include <algorithm>

namespace pe
{
	inline bool valid_pe( uintptr_t data )
	{
		if ( !data )
			return false;

		const auto dos = reinterpret_cast< IMAGE_DOS_HEADER* >( data );

		if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
			return false;

		if ( dos->e_lfanew <= 0 )
			return false;

		const auto nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( data + dos->e_lfanew );
		if ( nt->Signature != IMAGE_NT_SIGNATURE )
			return false;

		return true;
	}

	inline bool rva_to_offset( uintptr_t data, uint32_t rva, uint32_t& out_offset )
	{
		const auto dos = reinterpret_cast< IMAGE_DOS_HEADER* >( data );
		const auto nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( data + dos->e_lfanew );
		const auto sections = reinterpret_cast< IMAGE_SECTION_HEADER* >( reinterpret_cast< uint8_t* >( &nt->OptionalHeader ) + nt->FileHeader.SizeOfOptionalHeader );

		for ( uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i )
		{
			const auto& s = sections[ i ];

			const uint32_t section_start = s.VirtualAddress;
			const uint32_t section_size =
				std::max( s.SizeOfRawData, s.Misc.VirtualSize );

			if ( rva >= section_start &&
				 rva < section_start + section_size )
			{
				const uint32_t delta = rva - section_start;
				out_offset = s.PointerToRawData + delta;
				return true;
			}
		}

		return false;
	}

	inline std::string extract_filename( const char* full_path )
	{
		if ( !full_path )
			return {};

		const char* last = full_path;

		for ( const char* p = full_path; *p; ++p )
			if ( *p == '\\' || *p == '/' )
				last = p + 1;

		return std::string( last );
	}

	inline std::string get_pdb_filename( uintptr_t data )
	{
		if ( !valid_pe( data ) )
			return {};

		const auto dos =
			reinterpret_cast< const IMAGE_DOS_HEADER* >( data );

		const auto nt =
			reinterpret_cast< const IMAGE_NT_HEADERS64* >(
			data + dos->e_lfanew );

		if ( nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_DEBUG )
			return {};

		const auto& dir =
			nt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ];

		if ( !dir.VirtualAddress || !dir.Size )
			return {};

		uint32_t debug_offset {};
		if ( !rva_to_offset( data, dir.VirtualAddress, debug_offset ) )
			return {};

		const auto* debug = reinterpret_cast< const IMAGE_DEBUG_DIRECTORY* >( data + debug_offset );

		const size_t count = dir.Size / sizeof( IMAGE_DEBUG_DIRECTORY );

		for ( size_t i = 0; i < count; ++i )
		{
			if ( debug[ i ].Type != IMAGE_DEBUG_TYPE_CODEVIEW )
				continue;

			const auto cv = data + debug[ i ].PointerToRawData;

			if ( *( const uint32_t* )cv == 'SDSR' ) // RSDS
			{
				const char* pdb =
					reinterpret_cast< const char* >( cv + 24 );

				return extract_filename( pdb );
			}
		}

		return {};
	}

	inline bool save_to_disk( const std::string& file_name, uintptr_t data )
	{
		if ( !valid_pe( data ) )
			return false;

		const auto* dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( data );
		const auto* nt = reinterpret_cast< const IMAGE_NT_HEADERS64* >( data + dos->e_lfanew );

		size_t total_size = nt->OptionalHeader.SizeOfHeaders;
		const auto* sections = reinterpret_cast< const IMAGE_SECTION_HEADER* >( reinterpret_cast< const uint8_t* >( &nt->OptionalHeader ) + nt->FileHeader.SizeOfOptionalHeader );

		for ( uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i )
		{
			const auto& s = sections[ i ];

			size_t end = s.PointerToRawData + s.SizeOfRawData;

			if ( end > total_size )
				total_size = end;
		}

		const auto is_dll = nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
		const auto is_driver = nt->FileHeader.Characteristics & IMAGE_FILE_SYSTEM;
		std::string extension = ".bin";
		if ( is_dll )
		{
			extension = ".dll";
		}
		else if ( is_driver )
		{
			extension = ".sys";
		}
		else
		{
			// try to guess from subsystem
			switch ( nt->OptionalHeader.Subsystem )
			{
				case IMAGE_SUBSYSTEM_NATIVE:
				case IMAGE_SUBSYSTEM_WINDOWS_CUI:
					extension = ".exe";
					break;
				case IMAGE_SUBSYSTEM_WINDOWS_GUI:
					extension = ".exe";
					break;
				default:
					extension = ".bin";
					break;
			}
		}

		std::ofstream file( file_name + extension, std::ios::binary );
		if ( !file )
			return false;

		file.write( reinterpret_cast< const char* >( data ), total_size );
		file.close();
		return true;
	}
}