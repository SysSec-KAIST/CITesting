/**
 * Copyright 2013-2023 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#include "srsran/support/signal_handler.h"
#include "srsran/support/emergency_handlers.h"
#include <atomic>
#include <csignal>
#include <cstdio>
#include <unistd.h>

#ifndef SRSRAN_TERM_TIMEOUT_S
#define SRSRAN_TERM_TIMEOUT_S (5) // Temperary change the timeout value for connecting victim session when connected state
#endif

/// Handler called after the user interrupts the program.
static std::atomic<srsran_signal_hanlder> user_handler;
static std::atomic<srsran_signal_hanlder> initial_attach_handler;
static std::atomic<srsran_signal_hanlder> testing_attach_handler;

// test control handler
static void srsran_signal_handler(int signal)
{
  switch (signal) {
    case SIGALRM:
      // return;
      fprintf(stderr, "Couldn't stop after %ds. Forcing exit.\n", SRSRAN_TERM_TIMEOUT_S);
      execute_emergency_cleanup_handlers();
      raise(SIGKILL);
    case SIGUSR1:
      // fprintf(stdout, "********  Finish Initial Attach  ********\n");
      if (auto handler = initial_attach_handler.load()) {
        printf("[SIGUSR1] handler\n");
        handler();
      } else {
        return;
      }
      break;
    case SIGUSR2:
      // fprintf(stdout, "********  Finish Initial Attach  ********\n");
      // auto handler = testing_attach_handler.exchange(nullptr)
      // auto handler = testing_attach_handler.load()
      if (auto handler = testing_attach_handler.exchange(nullptr)) {
        printf("[SIGUSR2] handler\n");
        handler();
      } else {
        return;
      }
      break; 
    default:
      // all other registered signals try to stop the app gracefully
      // Call the user handler if present and remove it so that further signals are treated by the default handler.
      if (auto handler = user_handler.exchange(nullptr)) {
        printf("[SIGINT] handler\n");
        handler();
        // break;
      } else {
        return;
      }
      fprintf(stdout, "Stopping ..\n");
      // Temperary remove alarm function
      alarm(SRSRAN_TERM_TIMEOUT_S);
      //Temperary add signal
      
      break;
  }
}

void srsran_register_signal_handler(srsran_signal_hanlder handler)
{
  user_handler.store(handler);

  signal(SIGINT, srsran_signal_handler);
  signal(SIGTERM, srsran_signal_handler);
  signal(SIGHUP, srsran_signal_handler);
  signal(SIGALRM, srsran_signal_handler);
  
}

void srsran_custom_signal_handler(srsran_signal_hanlder handler)
{
  initial_attach_handler.store(handler);
  signal(SIGUSR1, srsran_signal_handler);
  signal(SIGUSR2, srsran_signal_handler);
}

void srsran_testing_signal_handler(srsran_signal_hanlder handler)
{
  testing_attach_handler.store(handler);
  signal(SIGUSR1, srsran_signal_handler);
  signal(SIGUSR2, srsran_signal_handler);
}