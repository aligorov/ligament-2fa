// ClassFactory.h — IClassFactory for LigamentProvider
#pragma once

#include "common.h"

namespace ligament {

class ClassFactory : public IClassFactory {
public:
    ClassFactory();
    virtual ~ClassFactory();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();

    // IClassFactory
    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject);
    IFACEMETHODIMP LockServer(BOOL fLock);

private:
    LONG m_cRef = 1;
};

} // namespace ligament
