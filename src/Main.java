import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.Security;

/**
 * Created by Lukas on 28-Mar-16.
 */
public class Main extends Application {

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new ConnectionAccepter().start();
        launch();
    }

    @Override
    public void start(Stage primaryStage) throws Exception {
        System.out.println("Starting GUI");
        primaryStage.getIcons().add(new Image("file:icon.png"));
        FXMLLoader loader = new FXMLLoader();
        loader.setLocation(getClass().getResource("OCSP.fxml"));
        Parent root = loader.load();
        primaryStage.setTitle("OCSP Server");
        Scene rootScene = new Scene(root);
        primaryStage.setScene(rootScene);
        primaryStage.show();
        primaryStage.setOnCloseRequest(e -> {
            Platform.exit();
            System.exit(0);
        });
    }
}
