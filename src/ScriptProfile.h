// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/Func.h"
#include "zeek/Stmt.h"

namespace zeek
	{

namespace detail
	{

class ScriptProfileStats
	{
public:
	ScriptProfileStats() { }
	ScriptProfileStats(std::string arg_name) : name(std::move(arg_name)) { }

	virtual ~ScriptProfileStats() { }

	const auto Name() const { return name; }

	int NumInstances() const { return ninstances; }
	int NumCalls() const { return ncalls; }
	double CPUTime() const { return CPU_time; }
	uint64_t Memory() const { return memory; }

	void AddInstance() { ++ninstances; }

	void AddIn(const ScriptProfileStats* eps, bool bump_num_calls = true)
		{
		if ( bump_num_calls )
			ncalls += eps->NumCalls();

		CPU_time += eps->CPUTime();
		memory += eps->Memory();
		}

	void AddIn(double delta_CPU_time, uint64_t delta_memory)
		{
		CPU_time += delta_CPU_time;
		memory += delta_memory;
		}

	void SetStats(double arg_CPU_time, uint64_t arg_memory)
		{
		CPU_time = arg_CPU_time;
		memory = arg_memory;
		}

	void NewCall() { ++ncalls; }

private:
	std::string name;

	int ninstances = 0;
	int ncalls = 0;
	double CPU_time = 0.0;
	uint64_t memory = 0;
	};

class ScriptProfile : public ScriptProfileStats
	{
public:
	ScriptProfile() : ScriptProfileStats("non-scripts")
		{
		func = nullptr;
		is_BiF = false;
		}

	ScriptProfile(const Func* _func, const detail::StmtPtr& body)
		: ScriptProfileStats(_func->Name())
		{
		func = _func;
		is_BiF = body == nullptr;

		if ( is_BiF )
			loc = *func->GetLocationInfo();
		else
			loc = *body->GetLocationInfo();
		}

	void StartActivation();
	void EndActivation();

	void ChildFinished(const ScriptProfile* child);

	bool IsBiF() const { return is_BiF; }

	double DeltaCPUTime() const { return delta_stats.CPUTime(); }
	uint64_t DeltaMemory() const { return delta_stats.Memory(); }

	void Report(FILE* f) const;

private:
	const Func* func;
	bool is_BiF;
	detail::Location loc;

	ScriptProfileStats child_stats;

	// These are ephemeral, relevant between Start and End activations.
	ScriptProfileStats start_stats;

	// Defined for the last activation period.
	ScriptProfileStats delta_stats;
	};

class ScriptProfileMgr
	{
public:
	ScriptProfileMgr(FILE* _f);
	~ScriptProfileMgr();

	void StartInvocation(const Func* f, const detail::StmtPtr& body = nullptr);
	void EndInvocation();

private:
	FILE* f;
	ScriptProfile non_scripts;
	std::vector<ScriptProfile*> call_stack;
	std::unordered_map<const Obj*, std::unique_ptr<ScriptProfile>> profiles;
	std::unordered_map<const Obj*, const Func*> body_to_func;
	std::vector<const Obj*> objs; // just for more natural printing order
	};

// If non-nil, script profiling is active.
extern std::unique_ptr<ScriptProfileMgr> spm;

	} // namespace zeek::detail

// Called to turn on script profiling to the given file.  If nil, writes
// the profile to stdout.
extern void activate_script_profiling(const char* fn);

	} // namespace zeek
