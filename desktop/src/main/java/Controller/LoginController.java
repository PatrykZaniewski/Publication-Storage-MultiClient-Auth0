package Controller;

import Config.RedisHandler;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.input.MouseEvent;
import javafx.stage.Stage;

import java.io.IOException;

public class LoginController {

    @FXML
    public Button loginButton;
    public TextField loginField;
    public PasswordField passwordField;
    public Label errorLabel;

    public void submit(MouseEvent mouseEvent) throws IOException {
        RedisHandler redisHandler = new RedisHandler("localhost", 6379);
        if (!passwordField.getText().equals("") && !loginField.getText().equals("")) {
            if (loginField.getText().equals("smiglowiec@szturmowy.pl") &&  passwordField.getText().equals("apache123!")) {
                FXMLLoader loader = new FXMLLoader(getClass().getResource("/FXML/mainWindow.fxml"));

                Parent root = loader.load();

                MainWindowController mainWindowController = loader.getController();
                mainWindowController.setLogin(loginField.getText());
                mainWindowController.afterLoad();
                mainWindowController.setRedisHandler(redisHandler);


                Stage stage = new Stage();
                stage.setTitle("Publication Storage");
                Image icon = new Image("/Icons/icon.png");
                stage.getIcons().add(icon);
                stage.setScene(new Scene(root, 600, 400));
                stage.setResizable(false);
                stage.setMinHeight(200);
                stage.setMinWidth(200);
                stage.show();

                Stage currStage = (Stage) loginButton.getScene().getWindow();
                currStage.close();
            } else {
                errorLabel.setText("Nieprawidłowe dane logowania!");
            }
        } else {
            errorLabel.setText("Wypełnij wszystkie pola!");
        }
    }
}
