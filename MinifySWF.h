#include <stdio.h>
//#define MINIZ_HEADER_FILE_ONLY
#include "miniz.c"

#define MY_STD_CALL __stdcall
extern "C"
{
#include "lzma/LzmaLib.c"
#include "lzma/LzmaDec.c"
#include "lzma/LzmaEnc.c"
#include "lzma/LzFind.c"
#include "lzma/Alloc.c"
}
/*
#define fprintf(...) ((void)0)
#include "zopfli\zlib_container.h"
#include "zopfli\blocksplitter.c"
#include "zopfli\cache.c"
#include "zopfli\hash.c"
#include "zopfli\deflate.c"
#include "zopfli\gzip_container.c"
#include "zopfli\katajainen.c"
#include "zopfli\lz77.c"
#include "zopfli\squeeze.c"
#include "zopfli\tree.c"
#include "zopfli\util.c"
#include "zopfli\zlib_container.c"


Options options;
*/
unsigned long CRC32_MEM(const unsigned char* InStr, unsigned long len)
{
	//生成Crc32的查询表
	unsigned int Crc32Table[256] = {0};
	unsigned int Crc;
	for (unsigned int i = 0; i < 256; i++)
	{
		Crc = i;
		for (unsigned int j = 0; j < 8; j++)
		{
			if (Crc & 1)
				Crc = (Crc >> 1) ^ 0xEDB88320;
			else
				Crc >>= 1;
		}
		Crc32Table[i] = Crc;
	}

	//开始计算CRC32校验值
	Crc = 0xFFFFFFFF;

	//IDAT
	for (unsigned int i = 0; i < 4; i++)
	{
		Crc = (Crc >> 8) ^ Crc32Table[(Crc & 0xFF) ^ "IDAT"[i]];
	}

	for (unsigned int i = 0; i < len; i++)
	{
		Crc = (Crc >> 8) ^ Crc32Table[(Crc & 0xFF) ^ InStr[i]];
	}

	Crc ^= 0xFFFFFFFF;
	return Crc;
}

void MinifyPNG(HWND list, const wchar_t *file, bool SaveBak)
{
    ListBox_AddString(list, file);

    FILE *fp = _wfopen(file, L"rb");
    if(!fp)
    {
        ListBox_AddString(list, L"打开文件失败。");
        ListBox_AddString(list, L"");
        return;
    }
    fseek( fp, 0, SEEK_END);
    int FileLength = ftell(fp);
    fseek( fp, 0, SEEK_SET);

    BYTE *FileBuf = (BYTE*)malloc(FileLength);
    fread(FileBuf,1,FileLength,fp);
    fclose(fp);

    BYTE *ptr = FileBuf;

    if( FileLength<3 || ( memcmp(ptr,"FWS",3) && memcmp(ptr,"CWS",3) && memcmp(ptr,"ZWS",3) ) )
    {
        ListBox_AddString(list, L"不是SWF文件。");
        ListBox_AddString(list, L"");
        free(FileBuf);
        return;
    }

    if( memcmp(ptr,"ZWS",3)==0 )
    {
        ListBox_AddString(list, L"此文件已经经过LZMA压缩，跳过处理。");
        ListBox_AddString(list, L"");
        free(FileBuf);
        return;
    }

    int is_compress = ptr[0]=='C';
    int swf_version = ptr[3];

    DWORD len = *(DWORD*)(ptr+4);

    DWORD out_len = len - 8;
    BYTE *out_buf = 0;

    if(is_compress)
    {
        out_buf = (BYTE *)malloc(out_len);
    }
    else
    {
        out_buf = ptr+8;
    }

    if(!is_compress || mz_uncompress(out_buf, &out_len, ptr+8, FileLength-8)==MZ_OK)
    {
        ListBox_AddString(list, L"准备重新压缩。");

        unsigned char *new_data = (BYTE*)malloc(out_len*2);
        size_t new_size = out_len*2;

        size_t prop_size = 5;
        BYTE outProps[LZMA_PROPS_SIZE];
        LzmaCompress(new_data, &new_size, out_buf, out_len, outProps, &prop_size, 5, 1<<23, 3, 0, 2, 128, 2);

        //ZlibCompress(&options, out_buf, out_len, &zopfli_buf, &zopfli_size);
        free(out_buf);

        if(SaveBak)
        {
            wchar_t t_file[MAX_PATH];
            wcscpy(t_file, file);

            wchar_t *ext = wcsrchr(file,'\\') + 1;
            t_file[ext-file] = 0;
            wcscat(t_file, L"_");
            wcscat(t_file, ext);

            _wrename(file, t_file);
            //ListBox_AddString(list, L"备份文件完成。");
        }

        FILE *out = _wfopen(file, L"wb");
        if(!out)
        {
            ListBox_AddString(list, L"保存文件失败。");
            ListBox_AddString(list, L"");
            free(FileBuf);
            return;
        }

        if(swf_version<13) swf_version = 13;

        //SWF文件头
        fwrite("ZWS",1,3,out);
        fwrite((void*)&swf_version,1,1,out);


        //new_size+=8;
        fwrite((void*)&len,1,4,out);
        fwrite((void*)&new_size,1,4,out);
        fwrite(outProps,1,sizeof(outProps),out);
        //unsigned __int64 InBufLen = out_len;
        //fwrite((void*)&InBufLen,1,sizeof(InBufLen),out);
        fwrite(new_data,1,new_size,out);

        DWORD new_len = ftell(out);
        fclose(out);

        free(new_data);

        wchar_t temp[1024];
        swprintf(temp, L"压缩文件完毕。    文件：%d 字节 -> %d 字节    压缩率：%.2f%%", FileLength, new_len, 100.0*new_len/FileLength);
        ListBox_AddString(list, temp);

        ListBox_AddString(list, L"");
        free(FileBuf);
        return;
    }
    else
    {
        free(out_buf);
        ListBox_AddString(list, L"异常的SWF文件。");
        ListBox_AddString(list, L"");
        free(FileBuf);
        return;
    }

    return;
}
