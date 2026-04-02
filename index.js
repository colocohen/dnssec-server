/*
 * dnssec-server: DNS server for Node.js
 * Copyright 2025 colocohen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * This file is part of the open-source project hosted at:
 *     https://github.com/colocohen/dnssec-server
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */

import * as wire from './src/wire.js';
import * as server from './src/server.js';

export const createServer = server.createServer;
export const buildDnssecMaterial = server.buildDnssecMaterial;
export const encodeMessage = wire.encodeMessage;
export const decodeMessage = wire.decodeMessage;
export const parseZone = wire.parseZone;
export const answerFromZone = server.answerFromZone;

export default {
  createServer,
  buildDnssecMaterial,
  encodeMessage,
  decodeMessage,
  parseZone,
  answerFromZone
};