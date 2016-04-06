import javafx.application.Application;
import javafx.application.Platform;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.stage.Stage;

/**
 * Created by Lukas on 06-Apr-16.
 */
public class GUIStarter extends Application implements Runnable {

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

    /*public void startGUI(String[] args) {
        launch(args);
    }*/

    @Override
    public void run() {
        launch();
    }
}
