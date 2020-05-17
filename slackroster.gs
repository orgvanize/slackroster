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
