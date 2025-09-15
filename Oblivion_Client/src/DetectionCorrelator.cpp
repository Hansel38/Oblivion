// Restored out-of-line implementation with category enum internally (header kept minimal)
#include "../pch.h"
#include "../include/DetectionCorrelator.h"
#include "../include/Config.h"
#include "../include/EventReporter.h"
#include "../include/Logger.h"
#include "../include/PipeClient.h"
#include <sstream>
#include <unordered_set>
#include <unordered_map>

namespace OblivionEye {
namespace {
	enum class Cat : uint8_t { EAT,IAT,PROLOG,SYSCALL,CE_PARTIAL,SIG_PARTIAL,EXT_HANDLE,OTHER };
	static Cat Map(const std::wstring &w){
		if(w==L"EAT")return Cat::EAT; if(w==L"IAT")return Cat::IAT; if(w==L"PROLOG")return Cat::PROLOG; if(w==L"SYSCALL")return Cat::SYSCALL; if(w==L"CE_PARTIAL")return Cat::CE_PARTIAL; if(w==L"SIG_PARTIAL")return Cat::SIG_PARTIAL; if(w==L"EXT_HANDLE")return Cat::EXT_HANDLE; return Cat::OTHER; }
	static std::string Narrow(const std::wstring &ws){ std::string s; s.reserve(ws.size()); for(auto c:ws) s.push_back((c>=32&&c<127)?(char)c:'?'); return s; }
	static std::string JsonEscape(const std::string &in){ std::string o; o.reserve(in.size()+8); for(char c:in){ switch(c){ case '"': o+="\\\""; break; case '\\': o+="\\\\"; break; case '\n': o+="\\n"; break; case '\r': o+="\\r"; break; case '\t': o+="\\t"; break; default: if((unsigned char)c < 0x20){ char buf[7]; snprintf(buf,sizeof(buf),"\\u%04X", (unsigned char)c); o+=buf; } else o.push_back(c); } } return o; }
	// Cooldown map lokal file: key = "HOOK|..." atau "MULTI|...", value = last sent tick
	static std::unordered_map<std::wstring, unsigned long long> g_lastDetectSent;
}

DetectionCorrelator &DetectionCorrelator::Instance(){ static DetectionCorrelator inst; return inst; }

void DetectionCorrelator::Prune(unsigned long long now){
	if(now - m_lastPruneTick < Config::CORR_PRUNE_INTERVAL_MS) return; m_lastPruneTick = now;
	++m_metricsPrunes;
	const unsigned window = Config::CORR_WINDOW_MS; size_t w=0; for(size_t i=0;i<m_entries.size();++i){ if(now - m_entries[i].tick <= window){ if(w!=i) m_entries[w]=m_entries[i]; ++w; } } if(w<m_entries.size()) m_entries.resize(w);
}

void DetectionCorrelator::Evaluate(unsigned long long now){
	++m_metricsEvaluations;
	unsigned eat=0,iat=0,prolog=0,syscall=0,ceP=0,sigP=0,extH=0; unsigned score=0; std::unordered_set<Cat> distinct;
	for(auto &e: m_entries){ if(now - e.tick > Config::CORR_WINDOW_MS) continue; score+=e.weight; Cat c=Map(e.cat); distinct.insert(c); switch(c){case Cat::EAT:++eat;break;case Cat::IAT:++iat;break;case Cat::PROLOG:++prolog;break;case Cat::SYSCALL:++syscall;break;case Cat::CE_PARTIAL:++ceP;break;case Cat::SIG_PARTIAL:++sigP;break;case Cat::EXT_HANDLE:++extH;break;default:break;} }
	if(score >= Config::CORR_SCORE_THRESHOLD && (eat+iat+prolog+syscall)>0){
		std::wstringstream combo; combo<<eat<<L"-"<<iat<<L"-"<<prolog<<L"-"<<syscall; std::wstring comboKey = combo.str();
		std::wstring cooldownKey = L"HOOK|" + comboKey; auto it = g_lastDetectSent.find(cooldownKey);
		bool cooldownOk = (it==g_lastDetectSent.end()) || (now - it->second >= Config::CORR_DETECTION_COOLDOWN_MS);
		if(cooldownOk && m_sentCombos.insert(comboKey).second){
			g_lastDetectSent[cooldownKey] = now;
			++m_metricsHookDetections; m_lastHookDetectTick = now;
			std::wstringstream msg; msg<<L"HookCorrelation score="<<score<<L" (EAT="<<eat<<L" IAT="<<iat<<L" PROLOG="<<prolog<<L" SYSCALL="<<syscall<<L" CEp="<<ceP<<L" SIGp="<<sigP<<L" HANDLE="<<extH<<L")"; EventReporter::SendDetection(L"HookCorrelation", msg.str()); Log(msg.str()); if(PipeClient::Instance().IsRunning()) PipeClient::Instance().Send("INFO|CORR|HOOK|"+Narrow(msg.str()));
		}
	}
	if(distinct.size() >= Config::CORR_TRIGGER_DISTINCT && (ceP+sigP+extH)>0){
		std::wstringstream combo; combo<<eat<<L"-"<<iat<<L"-"<<prolog<<L"-"<<syscall<<L"-"<<ceP<<L"-"<<sigP<<L"-"<<extH; std::wstring comboKey = combo.str();
		std::wstring cooldownKey = L"MULTI|" + comboKey; auto it = g_lastDetectSent.find(cooldownKey);
		bool cooldownOk = (it==g_lastDetectSent.end()) || (now - it->second >= Config::CORR_DETECTION_COOLDOWN_MS);
		if(cooldownOk && m_sentCombos.insert(L"MULTI-"+comboKey).second){
			g_lastDetectSent[cooldownKey] = now;
			++m_metricsMultiDetections; m_lastMultiDetectTick = now;
			std::wstringstream msg; msg<<L"MultiSourceCorrelation distinct="<<distinct.size()<<L" score="<<score<<L" (EAT="<<eat<<L" IAT="<<iat<<L" PROLOG="<<prolog<<L" SYSCALL="<<syscall<<L" CEp="<<ceP<<L" SIGp="<<sigP<<L" HANDLE="<<extH<<L")"; EventReporter::SendDetection(L"MultiCorr", msg.str()); Log(msg.str()); if(PipeClient::Instance().IsRunning()) PipeClient::Instance().Send("INFO|CORR|MULTI|"+Narrow(msg.str()));
		}
	}
}
void DetectionCorrelator::Report(const std::wstring &category,const std::wstring &detail,int weight,bool highPriority){
	unsigned long long now=NowMs();
	std::lock_guard<std::mutex> lk(m_mtx);
	Prune(now);
	m_entries.push_back(Entry{category,detail,now,weight});
	if(highPriority) {
		Evaluate(now);
	} else if(now - m_lastStatusSnapshot > Config::CORR_STATUS_SNAPSHOT_MS){
		Evaluate(now);
		m_lastStatusSnapshot = now;
	}
}

std::wstring DetectionCorrelator::GetStatus(){
	unsigned long long now=NowMs();
	std::lock_guard<std::mutex> lk(m_mtx);
	Prune(now);
	unsigned eat=0,iat=0,prolog=0,syscall=0,ceP=0,sigP=0,extH=0; unsigned score=0;
	for(auto &e:m_entries){ if(now - e.tick > Config::CORR_WINDOW_MS) continue; score+=e.weight; switch(Map(e.cat)){case Cat::EAT:++eat;break;case Cat::IAT:++iat;break;case Cat::PROLOG:++prolog;break;case Cat::SYSCALL:++syscall;break;case Cat::CE_PARTIAL:++ceP;break;case Cat::SIG_PARTIAL:++sigP;break;case Cat::EXT_HANDLE:++extH;break;default:break;} }
	std::wstringstream ss; ss<<L"score="<<score<<L" eat="<<eat<<L" iat="<<iat<<L" prolog="<<prolog<<L" syscall="<<syscall<<L" ceP="<<ceP<<L" sigP="<<sigP<<L" handle="<<extH; return ss.str();
}
void DetectionCorrelator::Reset(){
	std::lock_guard<std::mutex> lk(m_mtx);
	m_entries.clear();
	m_sentCombos.clear();
	m_lastStatusSnapshot = 0;
	m_lastPruneTick = 0;
	m_metricsEvaluations = 0;
	m_metricsPrunes = 0;
	m_metricsHookDetections = 0;
	m_metricsMultiDetections = 0;
	m_lastHookDetectTick = 0;
	m_lastMultiDetectTick = 0;
}
std::string DetectionCorrelator::GetStatusJson(){ unsigned long long now=NowMs(); std::lock_guard<std::mutex> lk(m_mtx); Prune(now); unsigned eat=0,iat=0,prolog=0,syscall=0,ceP=0,sigP=0,extH=0; unsigned score=0; for(auto &e:m_entries){ if(now - e.tick > Config::CORR_WINDOW_MS) continue; score+=e.weight; switch(Map(e.cat)){case Cat::EAT:++eat;break;case Cat::IAT:++iat;break;case Cat::PROLOG:++prolog;break;case Cat::SYSCALL:++syscall;break;case Cat::CE_PARTIAL:++ceP;break;case Cat::SIG_PARTIAL:++sigP;break;case Cat::EXT_HANDLE:++extH;break;default:break;} } std::ostringstream os; os<<"{\"score\":"<<score
	<<",\"eat\":"<<eat
	<<",\"iat\":"<<iat
	<<",\"prolog\":"<<prolog
	<<",\"syscall\":"<<syscall
	<<",\"ceP\":"<<ceP
	<<",\"sigP\":"<<sigP
	<<",\"handle\":"<<extH
	<<",\"evals\":"<<m_metricsEvaluations
	<<",\"prunes\":"<<m_metricsPrunes
	<<",\"hookDet\":"<<m_metricsHookDetections
	<<",\"multiDet\":"<<m_metricsMultiDetections
	<<",\"lastHook\":"<<m_lastHookDetectTick
	<<",\"lastMulti\":"<<m_lastMultiDetectTick
	<<"}"; return os.str(); }

} // namespace OblivionEye
