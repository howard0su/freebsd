/*-
 * Copyright (c) 1998 Robert Nordier
 * All rights reserved.
 * Copyright (c) 2001 Robert Drehmel
 * All rights reserved.
 * Copyright (c) 2014 Nathan Whitehorn
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are freely
 * permitted provided that the above copyright notice and this
 * paragraph and the following disclaimer are duplicated in all
 * such forms.
 *
 * This software is provided "AS IS" and without any express or
 * implied warranties, including, without limitation, the implied
 * warranties of merchantability and fitness for a particular
 * purpose.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/sys/boot/amd64/boot1.efi/boot1.c 279738 2015-03-07 19:14:01Z trasz $");

#include <sys/param.h>
#include <machine/stdarg.h>

#include <efi.h>
#include <eficonsctl.h>

/* XXX: This belongs in an efifoo.h header. */
#define EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID \
         {0x8b843e20,0x8132,0x4852,0x90,0xcc,0x55,0x1a,0x4e,\
         0x4a,0x7f, 0x1c}

INTERFACE_DECL(_EFI_DEVICE_PATH_PROTOCOL);

typedef
CHAR16*
(EFIAPI *EFI_DEVICE_PATH_TO_TEXT_NODE) (
    IN struct _EFI_DEVICE_PATH *This,
    IN BOOLEAN                 DisplayOnly,
    IN BOOLEAN                 AllowShortCuts
    );

typedef
CHAR16*
(EFIAPI *EFI_DEVICE_PATH_TO_TEXT_PATH) (
    IN struct _EFI_DEVICE_PATH *This,
    IN BOOLEAN                 DisplayOnly,
    IN BOOLEAN                 AllowShortCuts
    );

typedef struct _EFI_DEVICE_PATH_TO_TEXT_PROTOCOL {
	EFI_DEVICE_PATH_TO_TEXT_NODE ConvertDeviceNodeToText;
	EFI_DEVICE_PATH_TO_TEXT_PATH ConvertDevicePathToText;
} EFI_DEVICE_PATH_TO_TEXT_PROTOCOL;

typedef int putc_func_t(char c, void *arg);

static const char digits[] = "0123456789abcdef";

static void panic(const char *fmt, ...) __dead2;
static int printf(const char *fmt, ...);
static int putchar(char c, void *arg);
static int vprintf(const char *fmt, va_list ap);

static int __printf(const char *fmt, putc_func_t *putc, void *arg, va_list ap);
static int __putc(char c, void *arg);
static int __puts(const char *s, putc_func_t *putc, void *arg);
static char *__uitoa(char *buf, u_int val, int base);
static char *__ultoa(char *buf, u_long val, int base);

EFI_SYSTEM_TABLE *systab;
EFI_HANDLE *image;

static void     
bcopy(const void *src, void *dst, size_t len)
{
	const char *s = src;
	char *d = dst;

	while (len-- != 0)
		*d++ = *s++;
}
   
static void
memcpy(void *dst, const void *src, size_t len)
{
	bcopy(src, dst, len);
}               

static void
bzero(void *b, size_t len)
{
	char *p = b;

	while (len-- != 0)
		*p++ = 0;
}
        
static int
strcmp(const char *s1, const char *s2)
{
	for (; *s1 == *s2 && *s1; s1++, s2++)
		;
	return ((u_char)*s1 - (u_char)*s2);
}

static EFI_GUID PXEBaseCodeGUID = EFI_PXE_BASE_CODE_PROTOCOL;
static EFI_GUID DevicePathGUID = DEVICE_PATH_PROTOCOL;
static EFI_GUID LoadedImageGUID = LOADED_IMAGE_PROTOCOL;
static EFI_GUID ConsoleControlGUID = EFI_CONSOLE_CONTROL_PROTOCOL_GUID;
static EFI_GUID DevicePathToTextGUID = EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;

static EFI_BLOCK_IO *bootdev;
static EFI_DEVICE_PATH *bootdevpath;
static EFI_HANDLE *bootdevhandle;
static EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *textProtocol;

static void
print_device(EFI_DEVICE_PATH *devpath)
{
	EFI_STATUS status;
	CHAR16 *text;

	if (textProtocol == NULL) {
		printf("Path %p", devpath);
		return;
	}
	text = textProtocol->ConvertDevicePathToText(devpath, TRUE, TRUE);
	if (text == NULL) {
		printf("Path %p", devpath);
		return;
	}
	systab->ConOut->OutputString(systab->ConOut, text);
	systab->BootServices->FreePool(text);
}

static void
try_pxe(EFI_HANDLE handle)
{
	EFI_LOADED_IMAGE *loadedImage;
	EFI_DEVICE_PATH *devpath;
	EFI_STATUS status;
	EFI_HANDLE imageHandle;

	status = systab->BootServices->HandleProtocol(handle,
	    &DevicePathGUID, (void **)&devpath);
	if (EFI_ERROR(status))
		return;

	printf(">> Trying PXE on ");
	print_device(devpath);
	printf(":\n");

	status = systab->BootServices->LoadImage(TRUE, image, devpath,
	    NULL, 0, &imageHandle);
	if (EFI_ERROR(status)) {
		printf("Failed to load image: %d\n", status);
		return;
	}
	
	status = systab->BootServices->HandleProtocol(imageHandle,
	    &LoadedImageGUID, (VOID **)&loadedImage);
	if (EFI_ERROR(status)) {
		printf("Loaded image doesn't support protocol: %d\n", status);
		systab->BootServices->UnloadImage(imageHandle);
		return;
	}

	loadedImage->DeviceHandle = handle;

	status = systab->BootServices->StartImage(imageHandle, NULL, NULL);
	if (EFI_ERROR(status))
		printf("Image failed to start: %d\n", status);
	systab->BootServices->UnloadImage(imageHandle);
}

EFI_STATUS efi_main(EFI_HANDLE Ximage, EFI_SYSTEM_TABLE* Xsystab)
{
	EFI_HANDLE *handles;
	EFI_BLOCK_IO *blkio;
	UINTN i, nifs;
	EFI_STATUS status;
	EFI_BOOT_SERVICES *BS;
	EFI_CONSOLE_CONTROL_PROTOCOL *ConsoleControl = NULL;

	systab = Xsystab;
	image = Ximage;

	BS = systab->BootServices;
	status = BS->LocateProtocol(&ConsoleControlGUID, NULL,
	    (VOID **)&ConsoleControl);
	if (status == EFI_SUCCESS)
		(void)ConsoleControl->SetMode(ConsoleControl,
		    EfiConsoleControlScreenText);
	status = BS->LocateProtocol(&DevicePathToTextGUID, NULL,
	    (VOID **)&textProtocol);
	if (status != EFI_SUCCESS)
		textProtocol = NULL;

	/* Query for the needed size for the array of handles. */
	nifs = 0;
	status = systab->BootServices->LocateHandle(ByProtocol,
	    &PXEBaseCodeGUID, NULL, &nifs, NULL);
	if (status == EFI_NOT_FOUND) {
		printf("No PXE-capable interfaces found\n");
		return (EFI_SUCCESS);
	}
	if (status != EFI_BUFFER_TOO_SMALL) {
		printf("Querying PXE interface list failed: %d\n", status);
		return (EFI_SUCCESS);
	}

	/* Fetch the array of handles. */
	status = systab->BootServices->AllocatePool(EfiLoaderData, nifs,
	    (VOID **)&handles);
	if (status != EFI_SUCCESS) {
		printf("Failed to allocate interface list: %d\n", status);
		return (EFI_SUCCESS);
	}
	status = systab->BootServices->LocateHandle(ByProtocol,
	    &PXEBaseCodeGUID, NULL, &nifs, handles);
	if (status != EFI_SUCCESS) {
		printf("Failed to populate PXE interface list: %d\n", status);
		return (EFI_SUCCESS);
	}
	nifs /= sizeof(handles[0]);

	for (i = 0; i < nifs; i++) {
		try_pxe(handles[i]);
	}

	printf("Failed to PXE boot\n");
	systab->BootServices->FreePool(handles);

	return (EFI_SUCCESS);
}

static int
printf(const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vprintf(fmt, ap);
	va_end(ap);
	return (ret);
}

static int
putchar(char c, void *arg)
{
	CHAR16 buf[2];

	if (c == '\n') {
		buf[0] = '\r';
		buf[1] = 0;
		systab->ConOut->OutputString(systab->ConOut, buf);
	}
	buf[0] = c;
	buf[1] = 0;
	systab->ConOut->OutputString(systab->ConOut, buf);
	return (1);
}

static int
vprintf(const char *fmt, va_list ap)
{
	int ret;

	ret = __printf(fmt, putchar, 0, ap);
	return (ret);
}

static int
__printf(const char *fmt, putc_func_t *putc, void *arg, va_list ap)
{
	char buf[(sizeof(long) * 8) + 1];
	char *nbuf;
	u_long ul;
	u_int ui;
	int lflag;
	int sflag;
	char *s;
	int pad;
	int ret;
	int c;

	nbuf = &buf[sizeof buf - 1];
	ret = 0;
	while ((c = *fmt++) != 0) {
		if (c != '%') {
			ret += putc(c, arg);
			continue;
		}
		lflag = 0;
		sflag = 0;
		pad = 0;
reswitch:	c = *fmt++;
		switch (c) {
		case '#':
			sflag = 1;
			goto reswitch;
		case '%':
			ret += putc('%', arg);
			break;
		case 'c':
			c = va_arg(ap, int);
			ret += putc(c, arg);
			break;
		case 'd':
			if (lflag == 0) {
				ui = (u_int)va_arg(ap, int);
				if (ui < (int)ui) {
					ui = -ui;
					ret += putc('-', arg);
				}
				s = __uitoa(nbuf, ui, 10);
			} else {
				ul = (u_long)va_arg(ap, long);
				if (ul < (long)ul) {
					ul = -ul;
					ret += putc('-', arg);
				}
				s = __ultoa(nbuf, ul, 10);
			}
			ret += __puts(s, putc, arg);
			break;
		case 'l':
			lflag = 1;
			goto reswitch;
		case 'o':
			if (lflag == 0) {
				ui = (u_int)va_arg(ap, u_int);
				s = __uitoa(nbuf, ui, 8);
			} else {
				ul = (u_long)va_arg(ap, u_long);
				s = __ultoa(nbuf, ul, 8);
			}
			ret += __puts(s, putc, arg);
			break;
		case 'p':
			ul = (u_long)va_arg(ap, void *);
			s = __ultoa(nbuf, ul, 16);
			ret += __puts("0x", putc, arg);
			ret += __puts(s, putc, arg);
			break;
		case 's':
			s = va_arg(ap, char *);
			ret += __puts(s, putc, arg);
			break;
		case 'u':
			if (lflag == 0) {
				ui = va_arg(ap, u_int);
				s = __uitoa(nbuf, ui, 10);
			} else {
				ul = va_arg(ap, u_long);
				s = __ultoa(nbuf, ul, 10);
			}
			ret += __puts(s, putc, arg);
			break;
		case 'x':
			if (lflag == 0) {
				ui = va_arg(ap, u_int);
				s = __uitoa(nbuf, ui, 16);
			} else {
				ul = va_arg(ap, u_long);
				s = __ultoa(nbuf, ul, 16);
			}
			if (sflag)
				ret += __puts("0x", putc, arg);
			ret += __puts(s, putc, arg);
			break;
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			pad = pad * 10 + c - '0';
			goto reswitch;
		default:
			break;
		}
	}
	return (ret);
}

static int
__puts(const char *s, putc_func_t *putc, void *arg)
{
	const char *p;
	int ret;

	ret = 0;
	for (p = s; *p != '\0'; p++)
		ret += putc(*p, arg);
	return (ret);
}

static char *
__uitoa(char *buf, u_int ui, int base)
{
	char *p;

	p = buf;
	*p = '\0';
	do
		*--p = digits[ui % base];
	while ((ui /= base) != 0);
	return (p);
}

static char *
__ultoa(char *buf, u_long ul, int base)
{
	char *p;

	p = buf;
	*p = '\0';
	do
		*--p = digits[ul % base];
	while ((ul /= base) != 0);
	return (p);
}

