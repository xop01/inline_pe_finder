#include <Windows.h>
#include <iostream>
#include <vector>
#include <fstream>
#include "scanner.hpp"
#include "pe.hpp"

int main( int argc, char* argv [] )
{
	if ( argc < 2 )
	{
		std::printf( "[ ipf ] usage: %s <file_path>\n", argv[ 0 ] );
		system( "pause" );
		return 1;
	}

	std::vector<uint8_t> file_bytes = [ & ] () -> std::vector<uint8_t>
	{
		std::vector<uint8_t> bytes;

		std::ifstream file( argv[ 1 ], std::ios::binary | std::ios::ate );
		if ( !file )
			return {};

		std::streamsize size = file.tellg();
		if ( size <= 0 )
			return {};

		bytes.resize( static_cast< size_t >( size ) );

		file.seekg( 0, std::ios::beg );
		file.read( reinterpret_cast< char* >( bytes.data() ), size );

		return bytes;
	}( );

	if ( file_bytes.empty() )
	{
		std::printf( "[ ipf ] failed to read file: %s\n", argv[ 1 ] );
		system( "pause" );
		return 1;
	}

	std::printf( "[ ipf ] processing inline pe inside: %s\n", argv[ 1 ] );

	const auto pe_end = reinterpret_cast< uintptr_t >( file_bytes.data() + file_bytes.size() );
	auto pe = scanner::pattern_scan( file_bytes.data() + 1, pe_end, "4D 5A 90 00 ? 00" );
	if ( !pe )
	{
		std::printf( "[ ipf ] no inline pe found\n" );
		system( "pause" );
		return 1;
	}

	int pe_count = 1;
	while ( pe )
	{
		std::printf( "[ ipf ] found inline pe at offset: 0x%x (pe count: %d)\n", pe - ( uintptr_t )file_bytes.data(), pe_count );

		std::string file_name = "dump_" + std::to_string( pe_count );
		const auto pe_pdb_name = pe::get_pdb_filename( pe );
		bool ret = false;
		if ( !pe_pdb_name.empty() && pe_pdb_name.size() <= 150 )
		{
			ret = pe::save_to_disk( file_name + "_" + pe_pdb_name, pe );
		}
		else
		{
			ret = pe::save_to_disk( file_name, pe );
		}

		if ( ret )
		{
			std::printf( "[ ipf ] successfully dumped inline pe to disk with name: %s\n", file_name.c_str() );
		}
		else
		{
			std::printf( "[ ipf ] failed to dump inline pe to disk with name: %s\n", file_name.c_str() );
		}

		pe = scanner::pattern_scan( ( uint8_t* )pe + 1, pe_end, "4D 5A 90 00 ? 00" );
		if ( pe )
			++pe_count;
	}

	std::printf( "[ ipf ] finished processing file: %s, dumped %d images\n", argv[ 1 ], pe_count );
	system( "pause" );
	return 0;
}