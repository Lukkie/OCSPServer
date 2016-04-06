import javafx.fxml.FXML;
import javafx.scene.control.Button;

/**
 * Created by Lukas on 06-Apr-16.
 */
public class Controller {

    @FXML
    private Button button;

    @FXML
    public void initialize() {
        button.setOnAction(event -> System.exit(0));
    }
}
