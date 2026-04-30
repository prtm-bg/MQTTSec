### Issue faced: Overfit of RF model

after trained with mqttset from kagle
RF model gave 0.1 error avg

after 15 epochs, retrain with acquired data
RF model error reduced to 0 error

Resolve #1: Retrain after 60 epochs instead of 15 AND Increase total epochs from 60 to 300 epochs