//
// This file is a part of UERANSIM project.
// Copyright (c) 2023 ALİ GÜNGÖR.
//
// https://github.com/aligungr/UERANSIM/
// See README, LICENSE, and CONTRIBUTING files for licensing details.
//

#include "udp_task.hpp"

#include <cstdint>
#include <cstring>
#include <set>

#include <ue/nts.hpp>
#include <utils/common.hpp>
#include <utils/constants.hpp>
#include <iostream>
#include <thread>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
static constexpr const int BUFFER_SIZE = 16384;
static constexpr const int LOOP_PERIOD = 1000;
static constexpr const int RECEIVE_TIMEOUT = 200;
static constexpr const int HEARTBEAT_THRESHOLD = 2000; // (LOOP_PERIOD + RECEIVE_TIMEOUT)'dan büyük olmalı
InetAddress peerAddress1;
uint8_t buffer1[BUFFER_SIZE];
uint8_t buffer[BUFFER_SIZE];
bool p_a=false, a= false, f= false;
int n;
 int sockfd;
   // uint8_t buffer[1024];
    struct sockaddr_in servaddr, cliaddr;
 socklen_t len;
#include <fcntl.h>
/*
void udpListener() {
    int sockfd;
    char buffer[1024];
    struct sockaddr_in servaddr, cliaddr;

    // Create socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(12000);

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        close(sockfd);
        return;
    }

    socklen_t len;
    int n;
    len = sizeof(cliaddr); // len is value/result

    std::cout << "Listening on port 12000" << std::endl;
    while (true) {
        n = recvfrom(sockfd, (char *)buffer, 1024, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
        buffer[n] = '\0';
        std::cout << "Received: " << buffer << std::endl;
       m_server->Send(peerAddress1, buffer, static_cast<size_t>(buffer.length()));

        // Process the received packet here
    }

    close(sockfd);
}
*/
namespace nr::ue
{

RlsUdpTask::RlsUdpTask(TaskBase *base, RlsSharedContext *shCtx, const std::vector<std::string> &searchSpace)
    : m_server{}, m_ctlTask{}, m_shCtx{shCtx}, m_searchSpace{}, m_cells{}, m_cellIdToSti{}, m_lastLoop{},
      m_cellIdCounter{}
{
    m_logger = base->logBase->makeUniqueLogger(base->config->getLoggerPrefix() + "rls-udp");

    m_server = new udp::UdpServer();

    for (auto &ip : searchSpace)
        m_searchSpace.emplace_back(ip, cons::RadioLinkPort);

    m_simPos = Vector3{};
}

void RlsUdpTask::udpListener() {
//    int sockfd;
   // uint8_t buffer[1024];
 //   struct sockaddr_in servaddr, cliaddr;
 //   int flags = fcntl(sockfd, F_GETFL, 0);
  //  fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    // Create socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        std::cerr << "Socket creation failed" << std::endl;
        return;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(12000);

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        std::cerr << "Bind failed" << std::endl;
        close(sockfd);
        return;
    }

  //  socklen_t len;
    InetAddress addr;
    
    len = sizeof(cliaddr); // len is value/result
    int flags = fcntl(sockfd, F_GETFL, 0);
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
   // std::cout << "Listening on port 12000" << std::endl;
    while (true) {
        n = recvfrom(sockfd, buffer1, BUFFER_SIZE, MSG_WAITALL, (struct sockaddr *)&cliaddr, &len);
     //   buffer1[n] = '\0';
        if(n > 0)
{
        m_logger->debug( "Received:[%s] ", buffer1);
        auto rlsMsg = rls::DecodeRlsMessage(OctetView{buffer1, static_cast<size_t>(n)});
        if (rlsMsg == nullptr)
            m_logger->err("Unable to decode RLS message");
        if (rlsMsg->msgType == rls::EMessageType::HEARTBEAT)
    {
        for (auto &addr : m_searchSpace)
    {
m_logger->debug("sending heartbeat message");
 m_server->Send(addr, buffer1, static_cast<size_t>(sizeof(buffer1)));     
    }
}

else {
//f= true;
m_logger->debug("non HB");
  if(p_a)
{
    m_logger->debug("the problem may be here");
    m_server->Send(peerAddress1, buffer1, static_cast<size_t>(sizeof(buffer1)));
  // f= false;
}

}
}
/*
    if (a)
{
m_logger->debug(" sending reply[%s]", buffer);
sendto(sockfd, buffer, BUFFER_SIZE, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);// the buffersize may be issue
      //auto rlsMsg = rls::DecodeRlsMessage(OctetView{buffer, static_cast<size_t>(size)});
      // m_server->Send(peerAddress1, buffer, static_cast<size_t>(n+1));
auto rlsMsg = rls::DecodeRlsMessage(OctetView{buffer, static_cast<size_t>(sizeof(buffer))});
        if (rlsMsg == nullptr)
            m_logger->err("Unable to decode RLS message");
       else
{
 if(rlsMsg->msgType == rls::EMessageType::HEARTBEAT_ACK)
    {
m_logger->debug("ack");
}
else 
{
m_logger->debug("sending non-ack");
}
}
a= false;

        // Process the received packet here
    }*/
}
    m_logger->debug("closing connection");
    close(sockfd);
}

void RlsUdpTask::onStart()
{
//std::thread listenerThread(udpListener);

    // Ensure the listener thread runs alongside the main UE functionality
  //  listenerThread.detach();
std::thread listenerThread([this]() { this->udpListener(); });
    listenerThread.detach(); // Detach the thread to run independently
}
bool nt = true;
void RlsUdpTask::onLoop()
{
    auto current = utils::CurrentTimeMillis();
   // heartbeatCycle(current, m_simPos);
/*if (current - m_lastLoop > LOOP_PERIOD)
    {
        m_lastLoop = current;
        heartbeatCycle(current, m_simPos);
    }
  */
 //   uint8_t buffer[BUFFER_SIZE];
    InetAddress peerAddress;

    int size = m_server->Receive(buffer, BUFFER_SIZE, RECEIVE_TIMEOUT, peerAddress);
    if(!p_a)
{
    peerAddress1 = peerAddress;
}
//    m_logger->debug("peeraddress received");
    
    if (size > 0)
    {
     m_logger->debug(" message received from gnb[%s] ", buffer);
        a= true;
  p_a = true;
sendto(sockfd, buffer, size, MSG_CONFIRM, (const struct sockaddr *) &cliaddr, len);
/*    if(f)
{
    m_server->Send(peerAddress1, buffer1, static_cast<size_t>(sizeof(buffer1)));
   f= false;
}*/
}
        auto rlsMsg = rls::DecodeRlsMessage(OctetView{buffer, static_cast<size_t>(size)});
        if (rlsMsg == nullptr)
            m_logger->err("Unable to decode RLS message");
else {
        if (rlsMsg->msgType == rls::EMessageType::HEARTBEAT_ACK)
    {
m_logger->debug("ack");
}
else
{
m_logger->debug("non-ack");
}
}
 


   /*     else
             {
//std::cout<<"sent buffer"<<buffer;
           // receiveRlsPdu(peerAddress, std::move(rlsMsg));
            if(f)
{

           m_logger->debug("sending buffer");
auto rlsMsg = rls::DecodeRlsMessage(OctetView{buffer1, static_cast<size_t>(n)});

OctetString stream;
    rls::EncodeRlsMessage(*rlsMsg, stream);
 // rls::RlsMessage message(buffer1, sizeof(buffer1));

// Now pass the rls::RlsMessage object to EncodeRlsMessage
//rls::EncodeRlsMessage(message, stream);
   // rls::EncodeRlsMessage(buffer1, stream);
if (rlsMsg == nullptr)
            m_logger->err("Unable to decode RLS message");
          
            m_server->Send(peerAddress1, stream.data(), static_cast<size_t>(stream.length()));
    f= false;
}
}*/
//     receiveRlsPdu(peerAddress, std::move(rlsMsg));

    }
//}

void RlsUdpTask::onQuit()
{
    delete m_server;
}

void RlsUdpTask::sendRlsPdu(const InetAddress &addr, const rls::RlsMessage &msg)
{
    OctetString stream;
    rls::EncodeRlsMessage(msg, stream);
//    std::cout<<addr.toString();
    m_server->Send(addr, stream.data(), static_cast<size_t>(stream.length()));
}

void RlsUdpTask::send(int cellId, const rls::RlsMessage &msg)
{
    if (m_cellIdToSti.count(cellId))
    {
        auto sti = m_cellIdToSti[cellId];
        sendRlsPdu(m_cells[sti].address, msg);
    }
}

void RlsUdpTask::receiveRlsPdu(const InetAddress &addr, std::unique_ptr<rls::RlsMessage> &&msg)
{
    if (msg->msgType == rls::EMessageType::HEARTBEAT_ACK)
    {
        if (!m_cells.count(msg->sti))
        {
            m_cells[msg->sti].cellId = ++m_cellIdCounter;
            m_cellIdToSti[m_cells[msg->sti].cellId] = msg->sti;
        }

        int oldDbm = INT32_MIN;
        if (m_cells.count(msg->sti))
            oldDbm = m_cells[msg->sti].dbm;

        m_cells[msg->sti].address = addr;
        m_cells[msg->sti].lastSeen = utils::CurrentTimeMillis();

        int newDbm = ((const rls::RlsHeartBeatAck &)*msg).dbm;
        m_cells[msg->sti].dbm = newDbm;

        if (oldDbm != newDbm)
            onSignalChangeOrLost(m_cells[msg->sti].cellId);
        return;
    }

    if (!m_cells.count(msg->sti))
    {
        // if no HB-ACK received yet, and the message is not HB-ACK, then ignore the message
        return;
    }

    auto w = std::make_unique<NmUeRlsToRls>(NmUeRlsToRls::RECEIVE_RLS_MESSAGE);
    w->cellId = m_cells[msg->sti].cellId;
    w->msg = std::move(msg);
   //a= true;
  //  m_ctlTask->push(std::move(w));
}

void RlsUdpTask::onSignalChangeOrLost(int cellId)
{
    int dbm = INT32_MIN;
    if (m_cellIdToSti.count(cellId))
    {
        auto sti = m_cellIdToSti[cellId];
        dbm = m_cells[sti].dbm;
    }

    auto w = std::make_unique<NmUeRlsToRls>(NmUeRlsToRls::SIGNAL_CHANGED);
    w->cellId = cellId;
    w->dbm = dbm;
    m_ctlTask->push(std::move(w));
}

void RlsUdpTask::heartbeatCycle(uint64_t time, const Vector3 &simPos)
{
    std::set<std::pair<uint64_t, int>> toRemove;

    for (auto &cell : m_cells)
    {
        auto delta = time - cell.second.lastSeen;
        if (delta > HEARTBEAT_THRESHOLD)
            toRemove.insert({cell.first, cell.second.cellId});
    }

    for (auto cell : toRemove)
    {
        m_cells.erase(cell.first);
        m_cellIdToSti.erase(cell.second);
    }

    for (auto cell : toRemove)
        onSignalChangeOrLost(cell.second);

    for (auto &addr : m_searchSpace)
    {
        rls::RlsHeartBeat msg{m_shCtx->sti};
        msg.simPos = simPos;
        sendRlsPdu(addr, msg);
    }
}

void RlsUdpTask::initialize(NtsTask *ctlTask)
{
    m_ctlTask = ctlTask;
}

} // namespace nr::ue
