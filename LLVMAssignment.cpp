//===- Hello.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Hello World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include <llvm/Support/CommandLine.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Support/ToolOutputFile.h>

#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>

#include <llvm/IR/Function.h>
#include <llvm/Pass.h>
#include <llvm/Support/raw_ostream.h>

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Instructions.h>


using namespace llvm;
static ManagedStatic<LLVMContext> GlobalContext;

static LLVMContext &getGlobalContext() { return *GlobalContext; }

#define Info Log(LogLevel::info)
#define Warning Log(LogLevel::warning)
#define Debug Log(LogLevel::debug)
#define Error Log(LogLevel::error)

enum class LogLevel {
    info = 0,
    debug,
    warning,
    error
};

class Log {
public:
    explicit Log(LogLevel level) : _level(level) {}

    ~Log() {
        output();
    }

    Log &operator<<(const std::string &message);

private:
    LogLevel _level;
    std::string _message;

    void output();
};

void Log::output() {
    if (_level == LogLevel::info) {
        errs() << "\033[32m[Info]: \033[0m" << _message << '\n';
    } else if (_level == LogLevel::warning) {
        errs() << "\033[35m[Warning]: 033[0m" << _message << '\n';
    } else if (_level == LogLevel::error) {
        errs() << "\033[31m[Error]: \033[0m" << _message << '\n';
    } else {
        errs() << "\033[34m[Debug]: \033[0m" << _message << '\n';
    }
}

Log &Log::operator<<(const std::string &message) {
    _message += message;
    return *this;
}


/* In LLVM 5.0, when  -O0 passed to clang , the functions generated with clang will
 * have optnone attribute which would lead to some transform passes disabled, like mem2reg.
 */
struct EnableFunctionOptPass : public FunctionPass {
    static char ID;

    EnableFunctionOptPass() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
        if (F.hasFnAttribute(Attribute::OptimizeNone)) {
            F.removeFnAttr(Attribute::OptimizeNone);
        }
        return true;
    }
};

char EnableFunctionOptPass::ID = 0;


///!TODO TO BE COMPLETED BY YOU FOR ASSIGNMENT 2
///Updated 11/10/2017 by fargo: make all functions
///processed by mem2reg before this pass.
struct FuncPtrPass : public ModulePass {
    static char ID; // Pass identification, replacement for typeid
    FuncPtrPass() : ModulePass(ID) {}

    std::map<unsigned int, std::vector<StringRef>> lineFuncMap;

    void insertFuncName(unsigned int lineno, StringRef funcName) {
        auto it = lineFuncMap.find(lineno);
        if (it == lineFuncMap.end()) {
            lineFuncMap.insert(std::make_pair(lineno, std::vector<StringRef>(1, funcName)));
        } else {
            it->second.push_back(funcName);
        }

    }

    void output() const {
        for (auto &out: lineFuncMap) {
            errs() << out.first << " : ";
            auto &funcNames = out.second;
            for (auto it = funcNames.begin(); it != funcNames.end(); it++) {
                if (it != funcNames.begin()) {
                    errs() << " ,";
                }
                errs() << *it;
            }
            errs() << "\n";
        }
    }

    void evalCallInst(const CallInst *callInst) {
        // getCalledFunction returns the function called,
        // or null if this is an indirect function invocation.
        auto lineno = callInst->getDebugLoc().getLine();
        if (auto *func = callInst->getCalledFunction()) {
            // 直接函数调用（或者已经被优化成直接调用的间接函数调用）
            if (func->isIntrinsic())
                return;
            StringRef funcName = func->getName().data();
//            if (funcName == "llvm.dbg.value") {
//                return;
//            }

            insertFuncName(lineno, funcName);
        }
//        else { // 非直接函数调用
//            Debug << "Indirect function invocation: " << *callInst;
//            const Value *value = callInst->getCalledOperand();
//            errs()("Value of indirect function invocation: " << *value);
//            if (const PHINode *phiNode = dyn_cast<PHINode>(value)) {
//                handlePHINode(phiNode);
//            } else {
//                Debug << "Unhandled CallOperand Value: " << *value;
//            }
//        }
//        insertFuncName(callInst->getDebugLoc().getLine());
    }

    bool runOnModule(Module &M) override {
        errs() << "Hello: ";
        errs().write_escaped(M.getName()) << '\n';
        M.dump();
        errs() << "------------------------------\n";

        for (Function &f: M) {
            for (BasicBlock &bb: f) {
                for (Instruction &i: bb) {
                    if (auto *callInst = dyn_cast<CallInst>(&i)) {
                        evalCallInst(callInst);
                    }
                }
            }
        }
        output();
        return true;
    }
};


char FuncPtrPass::ID = 0;
static RegisterPass<FuncPtrPass> X("funcptrpass", "Print function call instruction");

static cl::opt<std::string>
        InputFilename(cl::Positional,
                      cl::desc("<filename>.bc"),
                      cl::init(""));


int main(int argc, char **argv) {
    LLVMContext &Context = getGlobalContext();
    SMDiagnostic Err;
    // Parse the command line to read the Inputfilename
    cl::ParseCommandLineOptions(argc, argv,
                                "FuncPtrPass \n My first LLVM too which does not do much.\n");


    // Load the input module
    std::unique_ptr<Module> M = parseIRFile(InputFilename, Err, Context);
    if (!M) {
        Err.print(argv[0], errs());
        return 1;
    }

    llvm::legacy::PassManager Passes;

    ///Remove functions' optnone attribute in LLVM5.0
    Passes.add(new EnableFunctionOptPass());
    ///Transform it to SSA
    Passes.add(llvm::createPromoteMemoryToRegisterPass());

    /// Your pass to print Function and Call Instructions
    Passes.add(new FuncPtrPass());
    Passes.run(*M.get());
}

