package online.buzzzz.security.passwordprotect;

import java.net.URL;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.*;
import online.buzzzz.security.AESCrypto;

import com.google.api.client.auth.oauth2.Credential;
import com.google.api.client.extensions.java6.auth.oauth2.AuthorizationCodeInstalledApp;
import com.google.api.client.extensions.jetty.auth.oauth2.LocalServerReceiver;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleClientSecrets;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.googleapis.media.MediaHttpUploader;
import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.util.store.DataStoreFactory;
import com.google.api.client.util.store.FileDataStoreFactory;
import com.google.api.services.drive.Drive;
import com.google.api.services.drive.DriveRequest;
import com.google.api.services.drive.DriveScopes;
import com.google.api.services.drive.model.File;
import com.google.api.services.drive.model.FileList;
import java.io.ByteArrayOutputStream;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Collections;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;

public class FXMLController implements Initializable {
    
  private final String APPLICATION_NAME = "Password Protect";
  private final String FILE_NAME = "TextEncryptor";
  private final String MIME_TYPE = "text/plain";
  private final String FIELD_LIST = "files(id, name, trashed, mimeType)";

  /** Directory to store user credentials. */
  private final java.io.File DATA_STORE_DIR =
      new java.io.File(System.getProperty("user.home"), ".store/password_protect");

  /**
   * Global instance of the {@link DataStoreFactory}. The best practice is to make it a single
   * globally shared instance across your application.
   */
  private FileDataStoreFactory dataStoreFactory;

  /** Global instance of the HTTP transport. */
  private HttpTransport httpTransport;

  /** Global instance of the JSON factory. */
  private final JsonFactory JSON_FACTORY = JacksonFactory.getDefaultInstance();

  /** Global Drive API client. */
  private Drive drive;

  /** Authorizes the installed application to access user's protected data. */
  private Credential authorize() throws Exception {
    // load client secrets
    GoogleClientSecrets clientSecrets = GoogleClientSecrets.load(JSON_FACTORY,
        new InputStreamReader(FXMLController.class.getResourceAsStream("/client_secrets.json")));
    // set up authorization code flow
    GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
        httpTransport, JSON_FACTORY, clientSecrets,
        Collections.singleton(DriveScopes.DRIVE_FILE)).setDataStoreFactory(dataStoreFactory)
        .build();
    // authorize
    return new AuthorizationCodeInstalledApp(flow, new LocalServerReceiver()).authorize("user");
  }
  
  @FXML
  private PasswordField pass;
  @FXML
  private TextArea source;
  @FXML
  private Label status;
  
  @FXML
  private void doEncrypt(ActionEvent event){
      source.setText(AESCrypto.encrypt(pass.getText(), source.getText()));
  }
  @FXML
  private void doDecrypt(ActionEvent event){
      source.setText(AESCrypto.decrypt(pass.getText(), source.getText()));
  }
  @FXML
  private void doLoadFile(ActionEvent event){
    try {
        httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        dataStoreFactory = new FileDataStoreFactory(DATA_STORE_DIR);
        // authorization
        status.setText("Trying to get authorization...");
        
        Credential credential = authorize();
        // set up the global Drive instance
        status.setText("Authorization complete...");
        drive = new Drive.Builder(httpTransport, JSON_FACTORY, credential).setApplicationName(
            APPLICATION_NAME).build();
        
        String query = "name = '" + FILE_NAME + "' and trashed = false and mimeType = '" + MIME_TYPE + "'";
        Drive.Files.List list = drive.files().list();
        list.setQ(query);
        list.setFields(FIELD_LIST);
        
        StringProperty fileId = new SimpleStringProperty();
        status.setText("Searching for file...");
        FileList files = list.execute();
        if(files.getFiles().isEmpty()){
            status.setText("File not found!");
            Alert ex = new Alert(Alert.AlertType.ERROR, "File not found!!", ButtonType.OK);
            ex.showAndWait();
            return;
        }
        files.getFiles().forEach(fl->{
            fileId.setValue(fl.getId());
        });
        
        ByteArrayOutputStream out = new ByteArrayOutputStream();        
        Drive.Files.Get load = drive.files().get(fileId.getValue());
        status.setText("Downloading file...");        
        load.executeMediaAndDownloadTo(out);
        source.setText(out.toString("UTF-8"));
        status.setText("Download complete...");
                
    } catch (IOException e) {
        status.setText(e.getLocalizedMessage());
        Alert ex = new Alert(Alert.AlertType.ERROR, e.getLocalizedMessage(), ButtonType.OK);
        ex.showAndWait();
    } catch (Exception e) {
        status.setText(e.getLocalizedMessage());
        Alert ex = new Alert(Alert.AlertType.ERROR, e.getLocalizedMessage(), ButtonType.OK);
        ex.showAndWait();
    }        
  }
  @FXML
  private void doSaveFile(ActionEvent event){
    try {
        httpTransport = GoogleNetHttpTransport.newTrustedTransport();
        dataStoreFactory = new FileDataStoreFactory(DATA_STORE_DIR);
        // authorization
        status.setText("Trying to get authorization...");
        Credential credential = authorize();
        // set up the global Drive instance
        status.setText("Authorization complete...");
        drive = new Drive.Builder(httpTransport, JSON_FACTORY, credential).setApplicationName(
            APPLICATION_NAME).build();
        

        String query = "name = '" + FILE_NAME + "' and trashed = false and mimeType = '" + MIME_TYPE + "'";
        Drive.Files.List list = drive.files().list();
        list.setQ(query);
        list.setFields(FIELD_LIST);
        
        ByteArrayContent fileContent = ByteArrayContent.fromString(MIME_TYPE, source.getText());
        File fileMetadata = new File();
        fileMetadata.setName(FILE_NAME);
        fileMetadata.setMimeType(MIME_TYPE);
        StringProperty fileId = new SimpleStringProperty();
        status.setText("Searching for file...");
        FileList files = list.execute();
        DriveRequest saveHandle;
        if(files.getFiles().isEmpty()){
            saveHandle = drive.files().create(fileMetadata, fileContent);
            status.setText("File not found!, creating new one..");
        }else{
            files.getFiles().forEach(fl->{
                fileId.setValue(fl.getId());
            });
            saveHandle = drive.files().update(fileId.getValue(), fileMetadata, fileContent);
            status.setText("File found!, overwritting it..");
        }
        MediaHttpUploader uploader = saveHandle.getMediaHttpUploader();
        uploader.setDirectUploadEnabled(true);
        saveHandle.execute();
        status.setText("File saved!");
        
    } catch (IOException e) {
        status.setText(e.getLocalizedMessage());
        Alert ex = new Alert(Alert.AlertType.ERROR, e.getLocalizedMessage(), ButtonType.OK);
        ex.showAndWait();
    } catch (Exception e) {
        status.setText(e.getLocalizedMessage());
        Alert ex = new Alert(Alert.AlertType.ERROR, e.getLocalizedMessage(), ButtonType.OK);
        ex.showAndWait();
    }        
  }
  @Override
  public void initialize(URL url, ResourceBundle rb) {
      // TODO
  }


}
