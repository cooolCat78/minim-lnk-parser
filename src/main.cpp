#include <iostream>
#include <string>
#include "liblnk.h"
#include "libfwsi.h"


void parseLnk(const std::string& file_path) {
		liblnk_error_t* error = nullptr;
		liblnk_file_t* lnk_file = nullptr;

		if (liblnk_file_initialize(&lnk_file, nullptr) != 1) {
      return;
		}

		if (liblnk_file_open(
			lnk_file, file_path.c_str(), LIBLNK_ACCESS_FLAG_READ, nullptr) !=
			1) {
			liblnk_file_free(&lnk_file, &error);
			return;
		}
    size_t targetDatIdentifieraSize;
    if (liblnk_file_get_link_target_identifier_data_size(
			lnk_file, &targetDatIdentifieraSize, nullptr) != 1 ||
			targetDatIdentifieraSize == 0) {
			liblnk_file_free(&lnk_file, &error);
			return;
		}

		uint8_t* buffer = new uint8_t[targetDatIdentifieraSize];

		if (liblnk_file_copy_link_target_identifier_data(
			lnk_file, buffer, targetDatIdentifieraSize, nullptr) != 1) {
			delete [] buffer;
			liblnk_file_free(&lnk_file, &error);
			return;
		}

		libfwsi_item_list_t* shellItemList = nullptr;
		int ascii_codepage = 20127;

	 if (libfwsi_item_list_initialize(&shellItemList, nullptr) != 1) {
			delete [] buffer;
			liblnk_file_free(&lnk_file, &error);
			return;
		}
		if (libfwsi_item_list_copy_from_byte_stream(shellItemList,
			buffer,
			targetDatIdentifieraSize,
			ascii_codepage,
			nullptr) != 1) {
			delete [] buffer;
			libfwsi_item_list_free(&shellItemList, nullptr);
			liblnk_file_free(&lnk_file, &error);
			return;
		}
		delete [] buffer;
    int numItems = 0;
    if (libfwsi_item_list_get_number_of_items(shellItemList, &numItems, nullptr) != 1) {
		libfwsi_item_list_free(&shellItemList, nullptr);
		liblnk_file_free(&lnk_file, &error);
    return;
    }

    for (int shellItemIndex = 0; shellItemIndex < numItems; shellItemIndex++) {
	    libfwsi_item_t* item = nullptr;
	    int type;
	    uint8_t classType;

	    if (libfwsi_item_initialize(&item, nullptr) != 1) {
	      continue;
	    }

	    if (libfwsi_item_list_get_item(shellItemList, shellItemIndex, &item, nullptr) != 1) {
	      auto res = libfwsi_item_free(&item, nullptr);
	      continue;
	    }
    }

		if (liblnk_file_close(lnk_file, nullptr) != 0) {
			liblnk_file_free(&lnk_file, &error);
		}
		liblnk_file_free(&lnk_file, &error);
		libfwsi_item_list_free(&shellItemList, nullptr);
	}

  int main(int argc, char* argv[])
{
		if (argc < 2) {
			std::cout << "Insufficient number of arguments passed " << std::endl;
			return 1;
		}
		parseLnk(argv[1]);
    return 0;
}
