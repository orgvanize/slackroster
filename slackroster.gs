// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
//
// Copyright (C) 2020, Sol Boucher
// Copyright (C) 2020, The Vanguard Campaign Corps Mods (vanguardcampaign.org)

// @OnlyCurrentDoc

function doGet(request) {
  var bearer = request.parameter.access_token;
  if(!bearer)
    return ContentService.createTextOutput('Missing request parameter: access_token');
  
  var openid = JSON.parse(get('https://accounts.google.com/.well-known/openid-configuration'));
  var active = JSON.parse(get(openid.userinfo_endpoint, bearer));
  if(active.email != Session.getEffectiveUser().getEmail() || !active.email_verified)
  return ContentService.createTextOutput('Unauthorized user: ' + active.email);
  
  var email = request.parameter.email;
  if(!email)
    return ContentService.createTextOutput('Missing request parameter: email');
  
  var channel = request.parameter.channel;
  if(!channel)
    return ContentService.createTextOutput('Missing request parameter: channel');
  
  var folder = lookup('channel', channel);
  if(!folder)
    return ContentService.createTextOutput('Invalid request parameter: \'channel=' + channel + '\'');
  
  var account = lookup('email', email, email);
  folder = DriveApp.getFolderById(folder);
  if(folder.getAccess(account) != DriveApp.Permission.EDIT)
    folder.addEditor(account);
  return ContentService.createTextOutput();
}

function lookup(table, key, fallback = null) {
  if(!key)
    return fallback;
  
  var sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(table);
  if(sheet.getLastRow() <= 2)
    return fallback;
  
  var cell = sheet.getRange(2, 1, sheet.getLastRow() - 1)
                  .createTextFinder(key)
                  .matchEntireCell(true)
                  .findNext();
  if(!cell)
    return fallback;
  return sheet.getRange(cell.getRow(), 2).getValue();
}

function get(resource, authorization) {
  if(authorization)
    authorization = {
      headers: {
        Authorization: 'Bearer ' + authorization,
      },
    };
  return UrlFetchApp.fetch(resource, authorization).getContentText();
}
