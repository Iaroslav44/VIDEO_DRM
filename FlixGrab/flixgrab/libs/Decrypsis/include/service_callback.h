#pragma once

#include <string>
#include <cstdint>
#include "abstract_service.h"

class ServiceCallback
{
public:
    virtual void                OnNewService(AbstractDecryptService* service) = 0;
    virtual void                OnReleaseService(AbstractDecryptService* service) = 0;
   // virtual void                OnError(const std::string& status, const std::string& message) = 0;
    
    
protected:

    virtual ~ServiceCallback() {}


};

class SessionMessageCallback
{
public:
    virtual void OnResolveNewSessionPromise(uint32_t promise_id, const char* session_id, uint32_t session_id_size) = 0;

    virtual void OnSessionMessage(const char* session_id, uint32_t session_id_size, uint32_t message_type, const char* message, uint32_t message_size) = 0;

};