// @OnlyCurrentDoc

function doGet(request) {
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
  DriveApp.getFolderById(folder).addEditor(account);
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
