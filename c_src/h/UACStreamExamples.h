#include "UACryptoDef.h"
#include <string>
#include <fstream>
#include <sstream>
using namespace std;


/**
	\struct UAC_STREAM
	Интерфейс потока UAC_STREAM

	Контракт функции:
	UAC_STREAM.read( PVOID ctx, PVOID* pbuf, unsigned* psize )
	
	1) при вызове:
		- ctx == UAC_STREAM.context
		- pbuf != NULL
		- psize != NULL

	2) Если *pbuf == NULL (быстрый режим), то обработчик 
		- ДОЛЖЕН записать в (*pbuf) адрес своего буфера в контексте, содержащего данные;
		- НЕ ДОЛЖЕН использовать исходное значение *psize;
		- МОЖЕТ возвращать в своем буфере любое количество байт >0;

	3) Если *pbuf != NULL (стандартный режим), то обработчик 
		- ДОЛЖЕН копировать в (*pbuf) либо (*psize) очередных байт, 
			либо все оставшиеся байты из потока, если их меньше чем (*psize).

	4) Во всех режимах (быстрый, стандартный) обработчик 
		- ДОЛЖЕН записать в (*psize) количество возвращенных байт;
		- ДОЛЖЕН записать в (*psize) значение 0 после исчерпания данных.
		- ДОЛЖЕН вернуть значение функции UAC_SUCCESS (0), 
			если данные успешно прочитаны или достигнут конец потока
		- ДОЛЖЕН вернуть код ошибки, если произошла ошибка чтения данных.
			Код ошибки ДОЛЖЕН быть UAC_ERROR_STREAM 
			либо другой код приложения, больший чем ::UAC_MAX_ERROR
			


	Контракт функции:
	UAC_STREAM.write( PVOID ctx, PVOID buf, unsigned size )

	1) при вызове:
		- ctx == UAC_STREAM.context
		- Если size>0, то buf != NULL и содержит (size) байт данных.
		- Если size==0, то действий не требуется.

	2) обработчик 
		- ДОЛЖЕН записать (size) байт из буфера (buf) в поток
		- ДОЛЖЕН вернуть значение функции UAC_SUCCESS (0), 
			если данные успешно прочитаны или достигнут конец потока
		- ДОЛЖЕН вернуть код ошибки, если произошла ошибка чтения данных.
			Код ошибки ДОЛЖЕН быть UAC_ERROR_STREAM 
			либо другой код приложения, больший чем ::UAC_MAX_ERROR

*/

#define INFILE_BUFSIZE 4096

/**
	реализация потока чтения из файла с интерфейсом UAC_STREAM 
*/
class infile_uacstream
{
public:
    infile_uacstream( const char* file_name, std::ios_base::openmode file_options = std::ios_base::in)
		: file_stream_( file_name, file_options )
	{
		uac_stream_.context = this;
		uac_stream_.read = &read;
		uac_stream_.write = NULL;
	}
	PUAC_STREAM stream() { return &uac_stream_; }
	
protected:	
	static DWORD read( PVOID ctx, PVOID* pbuf, unsigned* psize ) { 
		return ((infile_uacstream*)ctx)->doread( pbuf, psize );
	}

	DWORD doread( PVOID* pbuf, unsigned* psize ) { 
		if (pbuf==NULL || psize==NULL)
			return UAC_ERROR_STREAM; // нарушен контракт UAC_STREAM.read

		if (*pbuf==NULL) { // Быстрый режим
			file_stream_.read( buf_, sizeof(buf_) );
			*pbuf = buf_;
		} else { // Стандартный режим
			file_stream_.read( (char*)(*pbuf), *psize );
		}
		*psize = file_stream_.gcount();
		return UAC_SUCCESS;
	}

	UAC_STREAM 	uac_stream_;
	ifstream	file_stream_;
	char 		buf_[INFILE_BUFSIZE];
};

/**
	реализация потока записи в файл с интерфейсом UAC_STREAM 
*/
class outfile_uacstream
{
public:
    outfile_uacstream( const char* file_name, std::ios_base::openmode file_options = std::ios_base::out )
		: file_stream_( file_name, file_options )
	{
		uac_stream_.context = this;
		uac_stream_.read = NULL;
		uac_stream_.write = &write;
	}
	PUAC_STREAM stream() { return &uac_stream_; }

protected:		
	static DWORD write( PVOID ctx, PVOID buf, unsigned size ) { 
		return ((outfile_uacstream*)ctx)->dowrite( buf, size );
	}
	DWORD dowrite( PVOID buf, unsigned size ) 
	{ 
		file_stream_.write( (const char*)buf, size );
		return file_stream_.fail() ? UAC_ERROR_STREAM : 0;
	}
	UAC_STREAM 	uac_stream_;
	ofstream	file_stream_;

};


/**
	реализация потока чтения из буфера в памяти с интерфейсом UAC_STREAM 
*/
class inmem_uacstream
{
public:
	inmem_uacstream( const void* static_data, size_t data_size, unsigned chunk_size=INFILE_BUFSIZE ) 
	{
		static_data_ = static_data;
		data_size_ = data_size;
		chunk_size_ = chunk_size;
		offset_ = 0;
		uac_stream_.context = this;
		uac_stream_.read = &read;
		uac_stream_.write = NULL;
	}
	PUAC_STREAM stream() { return &uac_stream_; }
	
protected:	
	static DWORD read( PVOID ctx, PVOID* pbuf, unsigned* psize ) { 
		return ((inmem_uacstream*)ctx)->doread( pbuf, psize );
	}

	unsigned has_bytes( unsigned required_bytes )
	{
		unsigned bytes = required_bytes;
		if (size_t(bytes) > data_size_ - offset_)
			bytes = unsigned(data_size_ - offset_);
		return bytes;
	}

	DWORD doread( PVOID* pbuf, unsigned* psize ) { 
		if (pbuf==NULL || psize==NULL)
			return UAC_ERROR_STREAM; // нарушен контракт UAC_STREAM.read
		unsigned bytes;
		if (*pbuf==NULL) { // Быстрый режим
			bytes = has_bytes( chunk_size_ );
			if (bytes > 0) {
				*pbuf = ((char*)static_data_)+offset_;
				offset_ += bytes;
			}
		} else { // Стандартный режим
			bytes = has_bytes( *psize );
			if (bytes > 0) {
				memcpy( *pbuf, ((const char*)static_data_)+offset_, bytes );
				offset_ += bytes;
			}
			*psize = bytes;			
		}
		*psize = bytes;			
		return UAC_SUCCESS;
	}

protected:
	UAC_STREAM 	uac_stream_;
	const void *static_data_;
	size_t		data_size_;
	size_t		offset_;
	unsigned	chunk_size_;

};

/**
	реализация потока записи в строку std::string с интерфейсом UAC_STREAM 
*/
class outstr_uacstream
{
public:
	outstr_uacstream() 
	{
		uac_stream_.context = this;
		uac_stream_.read = NULL;
		uac_stream_.write = &write;
	}
	PUAC_STREAM stream() { return &uac_stream_; }
	string		value() { return string_stream_.str(); }
protected:		
	static DWORD write( PVOID ctx, PVOID buf, unsigned size ) { 
		return ((outstr_uacstream*)ctx)->dowrite( buf, size );
	}
	DWORD dowrite( PVOID buf, unsigned size ) 
	{ 
		string_stream_.write( (const char*)buf, size );
		return string_stream_.fail() ? UAC_ERROR_STREAM : 0;
	}
	UAC_STREAM 		uac_stream_;
	ostringstream	string_stream_;

};
