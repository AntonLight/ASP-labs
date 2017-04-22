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

static is_address(num) {
  return num != -1 && num != 0 && num != 1;
}

static print_except_filter(filter) {
  auto f = filter;
  filter = textbss_base + filter;
  if (f == 4294967295) Message("\tFilter:        EXCEPTION_CONTINUE_EXECUTION\n");
  else if (f == 0) Message("\tFilter:        EXCEPTION_CONTINUE_SEARCH\n");
  else if (f == 1) Message("\tFilter:        EXCEPTION_EXECUTE_HANDLER\n");
  else Message("\tFilter:        0x%016x aka %s\n", filter, GetFunctionName(filter));
}

static print_handlers(addr) {
  auto num = Dword(addr);
  if (num == 0 && num > 3) return;
  addr = addr + 4;

  Message("\nFounded %x block handlers @ %x:\n", num, addr);
  auto i = 0;
  for (; i < num; i++, addr = addr + 16) {
    auto begin   = textbss_base + Dword(addr);
    auto end     = textbss_base + Dword(addr + 4);
    auto filter  = Dword(addr + 8);
    auto handler = Dword(addr + 12);
    Message("\tTry begin:     0x%016x aka %s\n"
            "\tTry end:       0x%016x aka %s\n",
            begin, GetFunctionName(begin),
            end, GetFunctionName(end));

    if (is_address(handler)) {
      handler = textbss_base + handler;
      print_except_filter(filter);
      Message("\tExcept block:  0x%016x aka %s\n",
              handler, GetFunctionName(handler));
    } else if (is_address(filter) && !is_address(handler)) {
      filter = textbss_base + filter;
      Message("\tFinally block: 0x%016x aka %s\n", filter, GetFunctionName(filter));
    } else {
      filter = textbss_base + filter;
      handler = textbss_base + handler;
      Message("\tCan't determine handler types: 0x%016x & 0x%016x", filter, handler);
    }
  }
}

static print_unwind_info(unwind_data) {
  unwind_data = unwind_data;

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

  if (flags && count) {
    auto offset = 4 + count * 2;
    if (count & 1) offset = offset + 2; 
    auto fn_handler = textbss_base + Dword(unwind_data + offset);
    auto name = GetFunctionName(fn_handler);
    Message("Function handler: %s @ 0x%016x\n", name, fn_handler);
    print_handlers(unwind_data + offset + 4);
  }
}

static main() {
  auto pdata = find_segment(".pdata");
  Message("Found .pdata: 0x%016x\n", pdata);

  auto addr = pdata;
  while (addr < SegEnd(pdata)) {
    do { // for quick goto-next
      auto func_start  = textbss_base + Dword(addr);
      auto func_end    = textbss_base + Dword(addr + 4);
      auto name        = GetFunctionName(func_start);
      auto unwind_data = textbss_base + Dword(addr + 8);
      if (func_end - func_start == 0) break;
      if (Byte(unwind_data) >> 3 == 0) break;
      if (name != "CFunc") break; // debug only
      if (func_start != 0 && func_end != 0) {
        Message("~~\tAddr: 0x%016x\n"
                "~~\tName: %s\n"
                "~~\tFunc start  @ 0x%016x\n"
                "~~\tFunc end    @ 0x%016x\n"
                "~~\tUnwind info @ 0x%016x \n",
                addr,
                name,
                func_start,
                func_end,
                unwind_data);
        print_unwind_info(unwind_data);
      }
    } while (0);
    addr = addr + 12;
  }
}
