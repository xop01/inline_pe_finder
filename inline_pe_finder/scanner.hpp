#pragma once
#include <stdint.h>
#include <stddef.h>

namespace scanner
{
	struct pattern_byte
	{
		uint8_t value;
		uint8_t wildcard;
	};

	__forceinline uint8_t hex_to_byte( char c )
	{
		if ( c >= '0' && c <= '9' ) return c - '0';
		if ( c >= 'A' && c <= 'F' ) return c - 'A' + 10;
		if ( c >= 'a' && c <= 'f' ) return c - 'a' + 10;
		return 0;
	}

	__forceinline size_t parse_pattern( const char* signature, pattern_byte* out )
	{
		size_t count = 0;

		while ( *signature )
		{
			if ( *signature == ' ' )
			{
				++signature;
				continue;
			}

			if ( *signature == '?' )
			{
				out[ count++ ] = { 0, 1 };

				if ( *( signature + 1 ) == '?' )
					++signature;

				++signature;
			}
			else
			{
				uint8_t high = hex_to_byte( *signature++ );
				uint8_t low = hex_to_byte( *signature++ );

				out[ count++ ] = { static_cast< uint8_t >( ( high << 4 ) | low ), 0 };
			}
		}

		return count;
	}

	template<typename T = uintptr_t>
	inline T pattern_scan( void* base, uintptr_t pe_end, const char* signature )
	{
		if ( !base || !signature || pe_end == 0 )
			return T {};

		pattern_byte pattern[ 128 ];
		const size_t pattern_length = parse_pattern( signature, pattern );
		if ( pattern_length == 0 )
			return T {};

		uint8_t* scan_start = static_cast< uint8_t* >( base );
		size_t scan_size = pe_end - uintptr_t( base );

		if ( pattern_length > scan_size )
			return T {};

		// last starting byte where pattern fits
		uint8_t* scan_end = scan_start + ( scan_size - pattern_length );

		const uint8_t first_byte = pattern[ 0 ].value;
		const uint8_t first_wild = pattern[ 0 ].wildcard;

		for ( uint8_t* current = scan_start; current <= scan_end; ++current )
		{
			if ( !first_wild && *current != first_byte )
				continue;

			uint8_t* mem_ptr = current + 1;
			pattern_byte* pat_ptr = &pattern[ 1 ];
			size_t remaining = pattern_length - 1;

			while ( remaining-- )
			{
				if ( !pat_ptr->wildcard && *mem_ptr != pat_ptr->value )
					goto next;

				++mem_ptr;
				++pat_ptr;
			}

			return reinterpret_cast< T >( current );

		next:
			continue;
		}

		return T {};
	}
}