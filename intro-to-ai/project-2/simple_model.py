import torch
import torch.nn as nn
import torch.optim as optim
from torchvision import datasets, transforms, models
from torch.utils.data import DataLoader
import copy

#initialize device
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print("Using device:", device)

#hyperparameters to be used
batch_size = 8       # smaller for ultra-fast CPU training
learning_rate = 0.001
num_epochs = 3       # only 3 epochs for speed
img_size = 112       # smaller images speed up convolutions

#transform imnages
train_transform = transforms.Compose([
    transforms.Resize((img_size, img_size)),
    transforms.RandomHorizontalFlip(),
    transforms.RandomRotation(15),
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406],
                         [0.229, 0.224, 0.225])
])

val_test_transform = transforms.Compose([
    transforms.Resize((img_size, img_size)),
    transforms.ToTensor(),
    transforms.Normalize([0.485, 0.456, 0.406],
                         [0.229, 0.224, 0.225])
])

#load split datasets
train_dataset = datasets.ImageFolder('kitchenware_split_final/train', transform=train_transform)
val_dataset   = datasets.ImageFolder('kitchenware_split_final/val', transform=val_test_transform)
test_dataset  = datasets.ImageFolder('kitchenware_split_final/test', transform=val_test_transform)

train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
val_loader   = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
test_loader  = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)

num_classes = len(train_dataset.classes)
print("Classes:", train_dataset.classes)

#load simple model
model = models.resnet18(weights=models.ResNet18_Weights.IMAGENET1K_V1)

#freeze layers for optimal CPU pertformance
for param in model.parameters():
    param.requires_grad = False
model.fc = nn.Linear(model.fc.in_features, num_classes)
model.fc.requires_grad = True

model = model.to(device)

#loss
criterion = nn.CrossEntropyLoss()
optimizer = optim.Adam(model.fc.parameters(), lr=learning_rate)

#training loop
best_val_acc = 0.0
best_model_wts = copy.deepcopy(model.state_dict())

for epoch in range(num_epochs):
    model.train()
    running_loss = 0
    correct = 0
    total = 0

    for batch_idx, (images, labels) in enumerate(train_loader, 1):
        images, labels = images.to(device), labels.to(device)

        optimizer.zero_grad()
        outputs = model(images)
        loss = criterion(outputs, labels)
        loss.backward()
        optimizer.step()

        #updates running stats
        running_loss += loss.item()
        _, predicted = torch.max(outputs, 1)
        total += labels.size(0)
        correct += (predicted == labels).sum().item()

        #print progress every 10 batches
        if batch_idx % 10 == 0 or batch_idx == len(train_loader):
            batch_acc = 100 * correct / total
            print(f"Epoch [{epoch+1}/{num_epochs}] "
                  f"Batch [{batch_idx}/{len(train_loader)}] "
                  f"Loss: {running_loss/batch_idx:.4f} "
                  f"Train Acc: {batch_acc:.2f}%")

    train_acc = 100 * correct / total
    print(f"Epoch [{epoch+1}/{num_epochs}] - Loss: {running_loss/len(train_loader):.4f}, Train Acc: {train_acc:.2f}%")

    #validation
    model.eval()
    val_correct = 0
    val_total = 0
    with torch.no_grad():
        for images, labels in val_loader:
            images, labels = images.to(device), labels.to(device)
            outputs = model(images)
            _, predicted = torch.max(outputs, 1)
            val_total += labels.size(0)
            val_correct += (predicted == labels).sum().item()
    val_acc = 100 * val_correct / val_total
    print(f"Validation Acc: {val_acc:.2f}%\n")

    #saves best model
    if val_acc > best_val_acc:
        best_val_acc = val_acc
        best_model_wts = copy.deepcopy(model.state_dict())
        torch.save(best_model_wts, "best_resnet18_ultrafast.pth")
        print(f"New best model saved with val acc: {best_val_acc:.2f}%\n")

#loads the best model and tests it out
model.load_state_dict(best_model_wts)
model.eval()

test_correct = 0
test_total = 0
with torch.no_grad():
    for images, labels in test_loader:
        images, labels = images.to(device), labels.to(device)
        outputs = model(images)
        _, predicted = torch.max(outputs, 1)
        test_total += labels.size(0)
        test_correct += (predicted == labels).sum().item()

test_acc = 100 * test_correct / test_total
print(f"Test Accuracy: {test_acc:.2f}%")
print("Best model weights saved as 'best_resnet18_ultrafast.pth'")
