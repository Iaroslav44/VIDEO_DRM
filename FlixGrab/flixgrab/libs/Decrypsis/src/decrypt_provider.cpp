#include "decrypt_provider.h"

#include <iostream>
#include <algorithm>

#include "cdm_host.h"

DecryptProvider::DecryptProvider()
{
    std::cout << "DecryptProvider::Constructor" << std::endl;
}

DecryptProvider::~DecryptProvider()
{
    std::cout << "DecryptProvider::Destructor" << std::endl;
}

AbstractDecryptService* DecryptProvider::GetService(const key_id_t& key_id)
{
    std::unique_lock<std::mutex> locker(mutex_);
    int keyCount = 0;
    for (auto service : services_) {
        Keys      key_storage;
        service->GetKeyIds(key_storage);
        for (auto key : key_storage.keys) {
            if (key_id == key.key_id) {
                return service;
            }
            keyCount++;
        }
    }

    std::cout << "::GetService key_id: " << std::string((const char*)key_id.data(), key_id.size()) << " not found! Totally " << keyCount << " keys in " << services_.size() << " services." << std::endl;
    return NULL;
}

AbstractDecryptService* DecryptProvider::WaitForService(const key_id_t& key_id, int timeout /*= -1*/)
{
    AbstractDecryptService* service = GetService(key_id);

    while (service == NULL) {
        if (WaitForService(timeout)) {
            service = GetService(key_id);
        }
        else
            break;
    }

    return service;
}

bool DecryptProvider::WaitForService(int timeout /*= -1*/)
{
    std::unique_lock<std::mutex> locker(mutex_);

    if (timeout < 0) {
        cond_var_.wait(locker);
        return true;
    }
    else if (timeout > 0) {
        return (std::cv_status::no_timeout == cond_var_.wait_for(locker, std::chrono::milliseconds(timeout)));
    }
    return true;
}

DecryptProvider* DecryptProvider::Instance()
{
    static DecryptProvider      provider;
    return &provider;
}

void DecryptProvider::AddService(AbstractDecryptService* service) {
        
    std::unique_lock<std::mutex> locker(mutex_);
    Keys      key_storage;
    service->GetKeyIds(key_storage);
    for (auto key_id : key_storage.keys) {
        std::cout << "key_id: " << std::string((const char*)key_id.key_id.data(), key_id.key_id.size()) << std::endl;
    }

    services_.push_back(service);
    
    cond_var_.notify_all();

    auto callbacks = callbacks_;
    locker.unlock();

    //Callbacks must be free of mutex;
    for (auto callback : callbacks) {
        callback->OnNewService(service);
    }

}

void DecryptProvider::RemoveService(AbstractDecryptService* service)
{
    std::unique_lock<std::mutex> locker(mutex_);
    std::cout << "Remove service: " << std::endl;
    Keys      key_storage;
    service->GetKeyIds(key_storage);
    for (auto key_id : key_storage.keys) {
        std::cout << "key_id: " << std::string((const char*)key_id.key_id.data(), key_id.key_id.size()) << std::endl;
    }

    services_.erase(std::remove(services_.begin(), services_.end(), service), services_.end());
        
    cond_var_.notify_all();
    auto callbacks = callbacks_;
    locker.unlock();

    for (auto callback : callbacks) {
        callback->OnReleaseService(service);
    }
}


void DecryptProvider::DestroyAll()
{
    std::unique_lock<std::mutex> locker(mutex_);

    for (auto& service : services_) {
        service->Finish();
    }
    services_.clear();
    if (host_) {
        session_cb_ = NULL;
        host_->Destroy();
    }        
}

void DecryptProvider::RegisterCallback(ServiceCallback* callback) {
    std::unique_lock<std::mutex> locker(mutex_);
    callbacks_.push_back(callback);
}

void DecryptProvider::UnregisterCallback(ServiceCallback* callback) {
    std::unique_lock<std::mutex> locker(mutex_);
    for (auto it = callbacks_.begin(); it != callbacks_.end(); ++it) {
        if (*it == callback) {
            callbacks_.erase(it);
            break;
        }
    }
}

void DecryptProvider::CreateSessionAndGenerateRequest(const uint8_t* init_data, int init_data_size, SessionMessageCallback* session_cb, bool verify_cdm)
{
    std::cout << "DecryptProvider::CreateSessionAndGenerateRequest ..." << std::endl;
    static const std::string key_system = "com.widevine.alpha";
    static const std::string host_name = "loc_host";
    static uintptr_t host_this = 0;
    host_ = (CdmIpcAbstract*)CdmHost::CreateCdmIpcInstance(key_system, host_name, host_this, verify_cdm);
    
    session_cb_ = session_cb;
    host_->Initialize(0, 0, 0);
	promise_id++; // increment on each new session

    cdm::SessionType session_type = cdm::SessionType::kTemporary;
    cdm::InitDataType init_data_type = cdm::InitDataType::kCenc;
    BufferHolder buf(init_data, init_data_size);
    BufferHolder stor;
    host_->CreateSessionAndGenerateRequest(promise_id, session_type, init_data_type, buf, 0, stor);
    // ...OnSessionMessage
}

void DecryptProvider::OnSessionMessage(const char* session_id, uint32_t session_id_size, uint32_t message_type, const char* message, uint32_t message_size)
{
    if(session_cb_)
        session_cb_->OnSessionMessage(session_id, session_id_size, message_type, message, message_size);
}

void DecryptProvider::UpdateSession(const char* session, int session_size, const char* license, int license_size)
{
    if (host_) {
        BufferHolder session_buf(session, session_size);
        BufferHolder license_buf(license, license_size);
        host_->UpdateSession(promise_id, session_buf, license_buf);
    }
}

void DecryptProvider::CloseSession(const char* , int , SessionMessageCallback* session_cb)
{
    std::cout << "DecryptProvider::CloseSession ..." << std::endl;
    if(host_)
        host_->Destroy();
    if(session_cb == session_cb_)
        session_cb_ = NULL;
    host_ = NULL;
}