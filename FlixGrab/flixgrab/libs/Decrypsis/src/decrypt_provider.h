#pragma once

#include <string>
#include <vector>
#include <map>
#include <list>

#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>

#include "decrypt_protocol.h"

#include "service_callback.h"

#include "cdm_ipc.h"

typedef std::vector<uint8_t>        key_id_t;

//Singleton;
class DecryptProvider
{
public:
    
    AbstractDecryptService*     GetService(const key_id_t& key_id);

    AbstractDecryptService*     WaitForService(const key_id_t& key_id, int timeout = -1);

    bool                        WaitForService(int timeout = -1);

    void                        RegisterCallback(ServiceCallback* callback);
    void                        UnregisterCallback(ServiceCallback* callback);
    void                        CreateSessionAndGenerateRequest(const uint8_t* init_data, int init_data_size, SessionMessageCallback* session_cb, bool verify_cdm);
    void                        OnSessionMessage(const char* session_id, uint32_t session_id_size, uint32_t message_type, const char* message, uint32_t message_size);
    void                        UpdateSession(const char* session, int session_size, const char* license, int license_size);
    void                        CloseSession(const char* session, int session_size, SessionMessageCallback* session_cb);

public:

    static DecryptProvider*     Instance();

    bool                        Start() {
        cdm_server_ = std::make_unique<ipc::Server>(DEFAULT_CDM_IPC, SERVER_TABLE(CdmTable));
        return cdm_server_->status().Ok();
    }
    void                        Stop() {
        if (cdm_server_)
            cdm_server_->Cancel();
    }

public:
    void                        AddService(AbstractDecryptService*);
    void                        RemoveService(AbstractDecryptService*);
    void                        DestroyAll();

private:
    DecryptProvider();
    ~DecryptProvider();


private:
            
    std::vector<AbstractDecryptService*>                services_;
    
    std::mutex                                          mutex_;
    std::condition_variable                             cond_var_;

    std::list<ServiceCallback*>                         callbacks_;
    SessionMessageCallback*                             session_cb_ = NULL;
    CdmIpcAbstract*                                     host_ = NULL;
	uint32_t											promise_id = 1; // increment on each new session


private:
//TODO: remove
    std::unique_ptr<ipc::Server>                        cdm_server_;
    
};

