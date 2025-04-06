#ifndef WHS_SNIFF_HPP_
#define WHS_SNIFF_HPP_

#include <csignal>
#include <pcap/pcap.h>

#include <string>

namespace whs_sniff {

extern sig_atomic_t g_running;

class Sniff {
 public:
  // fp type alias
  using PacketHandler = bool(*)(const u_char*, const struct pcap_pkthdr*, const int);

  // occf
  Sniff(const char* interface, const char* filter, PacketHandler handler);
  ~Sniff(void);

  // error handler
  bool HasError(void) const;
  const std::string& ErrorMessage(void) const;

  //event loop
  void Loop(void);
  void SetEventHook(PacketHandler);

 private:
  // error variable
  std::string error_;
  char errorbuf_[PCAP_ERRBUF_SIZE];
  // pcap handle
  pcap_t* pcap_handle_;
  // event hook
  PacketHandler hook_;
  // sniffer info
  int packet_count_;
  
  // disable occf
  Sniff(const Sniff&) = delete;
  Sniff& operator=(const Sniff&) = delete;
};

// Signal management functions
void SetSignalHandler(void);
void HandleSignal(int signo, siginfo_t* info, void* ucontext);

}  // namespace whs_sniff

#endif  // WHS_SNIFF_HPP_
