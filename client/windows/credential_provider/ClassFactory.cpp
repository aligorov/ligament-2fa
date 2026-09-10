// ClassFactory.cpp — Implementation of IClassFactory
#include "ClassFactory.h"
#include "LigamentProvider.h"

namespace ligament {

extern LONG g_cRefDll;

ClassFactory::ClassFactory() {
    InterlockedIncrement(&g_cRefDll);
}

ClassFactory::~ClassFactory() {
    InterlockedDecrement(&g_cRefDll);
}

HRESULT ClassFactory::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(ClassFactory, IClassFactory),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

ULONG ClassFactory::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

ULONG ClassFactory::Release() {
    LONG c = InterlockedDecrement(&m_cRef);
    if (c == 0) delete this;
    return c;
}

HRESULT ClassFactory::CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) {
    if (pUnkOuter) return CLASS_E_NOAGGREGATION;
    if (!ppvObject) return E_POINTER;

    auto* pProvider = new LigamentProvider();
    if (!pProvider) return E_OUTOFMEMORY;

    HRESULT hr = pProvider->QueryInterface(riid, ppvObject);
    pProvider->Release();
    return hr;
}

HRESULT ClassFactory::LockServer(BOOL fLock) {
    if (fLock) {
        InterlockedIncrement(&g_cRefDll);
    } else {
        InterlockedDecrement(&g_cRefDll);
    }
    return S_OK;
}

} // namespace ligament
