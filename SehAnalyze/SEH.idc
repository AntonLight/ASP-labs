// structs grubbed from https://github.com/corkami/pocs/blob/master/PE/consts.inc
// some info also at http://blog.talosintelligence.com/2014/06/exceptional-behavior-windows-81-x64-seh.html
#include <idc.idc>

#define textbss_base 0x140000000
#define UNW_FLAG_EHANDLER 0x01
#define UNW_FLAG_UHANDLER 0x02
#define UNW_FLAG_CHAININFO 0x04

static find_segment(name) {
  auto seg;
  seg = FirstSeg();
  while (seg != BADADDR) {
    if (SegName(seg) == name) {
      return seg;
    }
    seg = NextSeg(seg);
  }
}

static print_flag(flag) {
  Message("\tFlags:");
  if (flag == 0) {
    Message("%s", " NO_FLAG");
  } else {
    if (flag & 1) {
      Message("%s", " UNW_FLAG_EHANDLER");
    }
    if (flag & 2) {
      Message("%s", " UNW_FLAG_UHANDLER");
    }
    if (flag & 4) {
      Message("%s", " UNW_FLAG_CHAININFO");
    }
  }
}

static print_unwind_info(unwind_data) {

  unwind_data = unwind_data + textbss_base;

  auto info = Byte(unwind_data);
  auto version = info & 0b111;
  auto flags = info >> 3;
  auto prolog = Byte(unwind_data + 1);
  auto count = Byte(unwind_data + 2);
  auto frame = Byte(unwind_data + 3);

  print_flag(flags);
  Message(" Version: %d "
          "Prolog size: %d "
          "Unwind codes count: %d "
          "Frame info: %b\n\n", // frame registers & offsets
          version, prolog,
          count, frame);
}

static main() {
  auto pdata = find_segment(".pdata");
  Message("Found .pdata: 0x%016x\n", pdata);

  auto addr = pdata;
  while (addr < SegEnd(pdata)) {
    do { // for quick goto-next
      auto func_start = Dword(addr);
      auto func_end = Dword(addr + 4);
      auto unwind_data = Dword(addr + 8);
      if (func_end - func_start == 0) break;
      if (func_start != 0 && func_end != 0) {
        Message("~~\tAddr: 0x%016x\n"
                "~~\tName: %s\n"
                "~~\tFunc start  @ 0x%016x\n"
                "~~\tFunc end    @ 0x%016x\n"
                "~~\tUnwind info @ 0x%016x \n",
                addr,
                GetFunctionName(textbss_base + func_start),
                func_start,
                func_end,
                unwind_data);
        print_unwind_info(unwind_data);
      }
    } while (0);
    addr = addr + 12;
  }
}
