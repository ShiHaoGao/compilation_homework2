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

    Log &operator<<(const std::string &message) {
        _message += message;
        return *this;
    }

    Log &operator<<(const int &message) {
        _message += std::to_string(message);
        return *this;
    }

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


    /*  当前Instruction结束，即清理 */
    using FuncNameList = std::set<StringRef>;
    using FuncList = std::set<Function *>;
    std::set<StringRef> funcNameList;
    std::set<Function *> funcList;
    std::map<Function *, Value *> func_user_map;

    /* 全局,不清理 */
    std::map<unsigned int, std::set<StringRef>> lineFuncMap;
    std::map<Value *, std::set<Function *>> callValue_Func_Map;


    void addFuncName(StringRef funcName) {
        funcNameList.insert(funcName);
    }

    void insertFuncNameList(unsigned int lineno) {
        Debug << "lineno: " << lineno;
        auto it = lineFuncMap.find(lineno);
        if (it == lineFuncMap.end()) {
            lineFuncMap.insert(std::pair(lineno, FuncNameList(funcNameList)));
        } else {
            Debug << "lineFuncMap has lineno";
            auto iter = lineFuncMap.find(lineno);
            auto list = iter->second;
            list.insert(funcNameList.begin(), funcNameList.end());
        }
    }

    void addFunction(Function *function) {
        funcList.insert(function);
    }

    void insertValueFuncMap(Value *callValue) {
        Debug << "Call Value name: " << callValue->getName();
        auto it = callValue_Func_Map.find(callValue);
        if (it == callValue_Func_Map.end()) {
            callValue_Func_Map.insert(std::pair(callValue, FuncList(funcList)));
        } else {
            Debug << "lineFuncMap has lineno";
            auto iter = callValue_Func_Map.find(callValue);
            auto list = iter->second;
            list.insert(funcList.begin(), funcList.end());
        }
    }

    FuncList getFuncList(Value *callValue) {
        Debug << "get call value name: " << callValue->getName();
        auto it = callValue_Func_Map.find(callValue);
        if (it != callValue_Func_Map.end()) {
            return it->second;
        } else {
            Error << "Get callValue's functionList error! There is not a " << callValue->getName() << "key!";
            return FuncList{};
        }
    }

    bool hasCallFunction(Value *callValue) {
        return callValue_Func_Map.find(callValue) != callValue_Func_Map.end();
    }

    bool hasCallValue(Function *func) {
        return func_user_map.find(func) != func_user_map.end();
    }

    Value *getCallValue(Function *func) {
        assert(func_user_map.find(func) != func_user_map.end());
        return func_user_map[func];
    }

    void clearTmpData() {
        funcList.clear();
        funcNameList.clear();
        func_user_map.clear();
    }

    void output() const {
        for (auto &out: lineFuncMap) {
            errs() << out.first << " : ";
            auto &funcNames = out.second;
            for (auto it = funcNames.begin(); it != funcNames.end(); it++) {
                if (it != funcNames.begin()) {
                    errs() << ", ";
                }
                errs() << *it;
            }
            errs() << "\n";
        }
    }

    // 处理是PHI结点的函数调用
    void evalPHINode(PHINode *phiNode) {
        Debug << "Eval PHINode!";
        for (Value *value: phiNode->incoming_values()) {
            evalValue(value);
        }
    }

    // 处理函数参数的函数调用
    void evalArgument(Argument *arg) {
        Debug << "Eval Arugment!";
        unsigned int argIdx = arg->getArgNo(); // 形参在函数参数中的位置
        auto *parentFunc = arg->getParent(); // 形参所在的函数

        // 获取参数所在函数的间接调用
        // 如果是间接调用，那么这个间接调用的CallValue已经被解析完成，并加入func_Value_map中，可以直接查找到user。
        if (hasCallValue(parentFunc)) {
            auto callValue = getCallValue(parentFunc);
            if (auto *callInst = dyn_cast<CallInst>(callValue)) {
                Value *operand = callInst->getArgOperand(argIdx);
                evalValue(operand);
            } else {
                Error << "Indirect call user of argument's parent function is not a CallInst";
            }
        }

        for (User *user: parentFunc->users()) {
            // 获取参数所在函数的直接调用
            if (auto *callInst = dyn_cast<CallInst>(user)) {
                Value *operand = callInst->getArgOperand(argIdx);
                evalValue(operand);
            } else {
                Error << "Indirect call user of argument's parent function";
            }
        }
    }

    // 处理直接函数调用。
    void evalFunction(Function *func) {
        Debug << "Function";
        addFuncName(func->getName().data());
        addFunction(func);
    }

    // 处理函数返回值的函数调用
    void evalFuncReturn(CallInst *callReturn) {
        Debug << "eval funcReturn!";
        if (auto *f = callReturn->getCalledFunction()) {
            evalReturnInst(f);
        } else if (auto callValue = callReturn->getCalledValue(); hasCallFunction(callValue)) {
            // 这个returnValue的callValue不是一个直接调用，那么这个value已经被分析过，在map中存放可能调用的值
            auto callFuncList = getFuncList(callValue);
            for (auto callFunc: callFuncList) {
                // function : indirect call value 保存起来，便于function寻找。
                func_user_map[callFunc] = callReturn;
                evalReturnInst(callFunc);
            }
        } else {
            Error << "FuncPointer of function return eval fail, because of function call is unknown. ";
        }

    }

    // 处理Indirect call value
    void evalValue(Value *value) {
        Debug << "Eval Value!";
        if (auto *func = dyn_cast<Function>(value)) {
            evalFunction(func);
        } else if (auto *phiNode = dyn_cast<PHINode>(value)) {
            evalPHINode(phiNode);
        } else if (auto *arg = dyn_cast<Argument>(value)) {
            evalArgument(arg);
        } else if (auto *callReturn = dyn_cast<CallInst>(value)) {
            evalFuncReturn(callReturn);
        } else {
            Error << "Unhandled CallOperand Value, can place \"NULL\" into function Name Set.";
//            addFuncName("NULL");
        }
    }

    void evalReturnInst(Function* f) {
        for (BasicBlock &bb: *f) {
            for (Instruction &i: bb) {
                if (auto *retInst = dyn_cast<ReturnInst>(&i)) {
                    Value *retValue = retInst->getReturnValue();
                    evalValue(retValue);
                }
            }
        }
    }

    void evalCallInst(Module &M) {
        for (Function &f: M) {
            for (BasicBlock &bb: f) {
                for (Instruction &i: bb) {
                    if (auto *callInst = dyn_cast<CallInst>(&i)) {
                        // 如果是llvm的debug信息，略过
                        if (auto *func = callInst->getCalledFunction())
                            if (func->isIntrinsic()) continue;
                        // 调用总dispatch函数，eval
                        auto *value = callInst->getCalledOperand();
                        evalValue(value);
                        // 将function call可能的函数加入set中
                        insertFuncNameList(callInst->getDebugLoc().getLine());
                        insertValueFuncMap(value);
                        // 清理局部暂存数据
                        clearTmpData();
                    }
                }
            }
        }
        output();
    }

    bool runOnModule(Module &M) override {
        errs() << "Hello: ";
        errs().write_escaped(M.getName()) << '\n';
        M.dump();
        errs() << "------------------------------\n";

        evalCallInst(M);
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

