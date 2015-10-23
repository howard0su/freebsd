/*-
 * XXX: License
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <efi.h>
#include <efilib.h>

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

static EFI_GUID DevicePathGUID = DEVICE_PATH_PROTOCOL;
static EFI_GUID DevicePathToTextGUID = EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;
static EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *textProtocol;

EFI_DEVICE_PATH *
efi_lookup_devpath(EFI_HANDLE handle)
{
	EFI_DEVICE_PATH *devpath;
	EFI_STATUS status;

	status = BS->HandleProtocol(handle, &DevicePathGUID, (VOID **)&devpath);
	if (EFI_ERROR(status))
		devpath = NULL;
	return (devpath);
}

CHAR16 *
efi_devpath_name(EFI_DEVICE_PATH *devpath)
{
	static int once = 1;
	EFI_STATUS status;

	if (devpath == NULL)
		return (NULL);
	if (once) {
		status = BS->LocateProtocol(&DevicePathToTextGUID, NULL,
		    (VOID **)&textProtocol);
		if (EFI_ERROR(status))
			textProtocol = NULL;
		once = 0;
	}
	if (textProtocol == NULL)
		return (NULL);

	return (textProtocol->ConvertDevicePathToText(devpath, TRUE, TRUE));
}

void
efi_free_devpath_name(CHAR16 *text)
{

	BS->FreePool(text);
}
